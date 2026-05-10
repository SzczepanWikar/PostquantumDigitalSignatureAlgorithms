using System.Collections;
using System.Diagnostics;
using System.Security.Cryptography;
using Core.Helpers;

namespace CrystalsDilithium.Algorithms
{
    internal sealed class PseudoRandomSampling
    {
        private readonly DilithiumParameters _parameters;
        private readonly BitAlgorithms _bitAlgorithms;

        public PseudoRandomSampling(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _bitAlgorithms = new BitAlgorithms(parameters);
        }

        /// <summary>
        /// Algorithm 29 — SampleInBall. Deterministically samples a polynomial c ∈ R_q with
        /// exactly τ non-zero coefficients, each ±1, from the seed <paramref name="rho"/>.
        /// Uses SHAKE-256: the first 8 output bytes supply the sign bits, subsequent bytes
        /// provide candidate positions via rejection sampling (Fisher-Yates shuffle).
        /// </summary>
        public int[] SampleInBall(byte[] rho)
        {
            int[] c = new int[256];
            Array.Fill(c, 0);

            using Shake256 shake256 = new();
            shake256.AppendData(rho);

            byte[] hash = shake256.Read(8);
            BitArray h = new BitArray(hash);

            byte[] buf = new byte[128];
            shake256.Read(buf);
            int pos = 0;

            for (int i = 256 - _parameters.Tau; i < 256; i++)
            {
                if (pos >= buf.Length)
                {
                    shake256.Read(buf);
                    pos = 0;
                }
                int j = buf[pos++];

                while (j > i)
                {
                    if (pos >= buf.Length)
                    {
                        shake256.Read(buf);
                        pos = 0;
                    }
                    j = buf[pos++];
                }

                c[i] = c[j];
                c[j] = h[i + _parameters.Tau - 256] ? -1 : 1;
            }

            return c;
        }

        /// <summary>
        /// Algorithm 30 — RejNTTPoly. Samples a uniform polynomial â ∈ T_q in NTT domain
        /// from the seed <paramref name="rho"/> using SHAKE-128 and rejection sampling via
        /// <see cref="BitAlgorithms.CoeffFromThreeBytes"/>. Reads 3 bytes per candidate
        /// and rejects values ≥ q.
        /// </summary>
        public int[] RejNTTPoly(byte[] rho)
        {
            short j = 0;

            using Shake128 shake = new();
            shake.AppendData(rho);

            int[] aDash = new int[256];

            while (j < 256)
            {
                byte[] s = shake.Read(3);
                int? coeff = _bitAlgorithms.CoeffFromThreeBytes(s[0], s[1], s[2]);

                if (coeff.HasValue)
                {
                    aDash[j] = coeff.Value;
                    j++;
                }
            }

            return aDash;
        }

        /// <summary>
        /// Algorithm 31 — RejBoundedPoly. Samples a polynomial with coefficients in S_η
        /// from the seed <paramref name="rho"/> using SHAKE-256 and rejection sampling via
        /// <see cref="BitAlgorithms.CoeffFromHalfByte"/>. Each output byte yields two
        /// 4-bit candidates (low and high nibble); candidates outside S_η are rejected.
        /// </summary>
        public int[] RejBoundedPoly(byte[] rho)
        {
            short j = 0;

            using Shake256 shake256 = new();
            shake256.AppendData(rho);

            int[] a = new int[256];

            while (j < 256)
            {
                byte z = shake256.Read(1)[0];
                int? z0 = _bitAlgorithms.CoeffFromHalfByte((byte)(z % 16));
                int? z1 = _bitAlgorithms.CoeffFromHalfByte((byte)(z / 16));

                if (z0.HasValue)
                {
                    a[j] = z0.Value;
                    j++;
                }

                if (z1.HasValue && j < 256)
                {
                    a[j] = z1.Value;
                    j++;
                }
            }

            return a;
        }

        /// <summary>
        /// Algorithm 32 — ExpandA. Derives the k×l matrix  of NTT-domain polynomials Â from
        /// the seed <paramref name="rho"/>. Entry Â[r][s] is obtained by calling
        /// <see cref="RejNTTPoly"/> with seed ρ ‖ IntToBytes(s, 1) ‖ IntToBytes(r, 1).
        /// </summary>
        public int[][][] ExpandA(byte[] rho)
        {
            int[][][] aHat = InitAHatMatrix();

            for (int r = 0; r < _parameters.AMatrixDimensions.K; r++)
            {
                for (int s = 0; s < _parameters.AMatrixDimensions.L; s++)
                {
                    byte[] rhoPrim = rho.Concat(_bitAlgorithms.IntegerToBytes(s, 1))
                        .Concat(_bitAlgorithms.IntegerToBytes(r, 1))
                        .ToArray();

                    aHat[r][s] = RejNTTPoly(rhoPrim);
                }
            }

            return aHat;
        }

        /// <summary>
        /// Algorithm 33 — ExpandS. Derives the secret polynomial vectors s1 ∈ S_η^l and
        /// s2 ∈ S_η^k from the seed <paramref name="rho"/>. Each polynomial is obtained by
        /// calling <see cref="RejBoundedPoly"/> with seed ρ' ‖ IntToBytes(r, 2), where r
        /// runs 0…l−1 for s1 and l…l+k−1 for s2.
        /// </summary>
        public (int[][] s1, int[][] s2) ExpandS(byte[] rho)
        {
            int[][] s1 = new int[_parameters.AMatrixDimensions.L][];
            int[][] s2 = new int[_parameters.AMatrixDimensions.K][];

            for (int r = 0; r < _parameters.AMatrixDimensions.L; r++)
            {
                byte[] bytes = ByteArrayHelpers.ConcatBytes(
                    rho,
                    _bitAlgorithms.IntegerToBytes(r, 2)
                );
                s1[r] = RejBoundedPoly(bytes);
            }

            for (int r = 0; r < _parameters.AMatrixDimensions.K; r++)
            {
                byte[] bytes = ByteArrayHelpers.ConcatBytes(
                    rho,
                    _bitAlgorithms.IntegerToBytes(r + _parameters.AMatrixDimensions.L, 2)
                );
                s2[r] = RejBoundedPoly(bytes);
            }

            return (s1, s2);
        }

        /// <summary>
        /// Algorithm 34 — ExpandMask. Derives the masking vector y ∈ S_{γ₁−1}^l from the
        /// seed <paramref name="rho"/> and nonce <paramref name="mi"/>. Each polynomial y[r]
        /// is produced by expanding seed ρ ‖ IntToBytes(κ + r, 2) with SHAKE-256 and decoding
        /// via <see cref="BitAlgorithms.BitUnpack"/> with bounds (γ₁−1, γ₁).
        /// </summary>
        public int[][] ExpandMask(byte[] rho, int mi)
        {
            Debug.Assert(mi >= 0, "Mask index must be non negative.");

            int[][] y = new int[_parameters.AMatrixDimensions.L][];
            int c = 1 + BitLength.GetNumberBitLength(_parameters.Gamma1 - 1);

            for (int r = 0; r < _parameters.AMatrixDimensions.L; r++)
            {
                byte[] rhoPrim = ByteArrayHelpers.ConcatBytes(
                    rho,
                    _bitAlgorithms.IntegerToBytes(mi + r, 2)
                );

                byte[] v = Shake256.HashData(rhoPrim, 32 * c);
                y[r] = _bitAlgorithms.BitUnpack(v, _parameters.Gamma1 - 1, _parameters.Gamma1);
            }

            return y;
        }

        private int[][][] InitAHatMatrix()
        {
            int[][][] aHat = new int[_parameters.AMatrixDimensions.K][][];

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                aHat[i] = new int[_parameters.AMatrixDimensions.L][];
            }

            return aHat;
        }
    }
}
