using System.Collections;
using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Dto;

namespace CrystalsDilithium.Algorithms.Operations
{
    internal sealed class Verifier
    {
        private readonly DilithiumParameters _parameters;
        private readonly Encoding _encoder;
        private readonly BitAlgorithms _bitAlgorithms;
        private readonly DilithiumFunctions _dilithiumFunctions;
        private readonly PseudoRandomSampling _pseudoRandomSampler;
        private readonly NttArithmetic _nttArithmetic;

        public Verifier(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _encoder = new(parameters);
            _bitAlgorithms = new(parameters);
            _dilithiumFunctions = new(parameters);
            _pseudoRandomSampler = new(parameters);
            _nttArithmetic = new(parameters);
        }

        /// <summary>
        /// Algorithm 8 — ML-DSA.Verify_internal. Verifies signature <paramref name="sigma"/>
        /// against public key <paramref name="pk"/> and padded message <paramref name="mPrim"/>.
        /// Decodes pk and σ, rejects if h is malformed, computes μ, reconstructs
        /// w'1 = UseHint(h, HighBits(Az − c·t1·2^d)), then accepts iff ‖z‖∞ &lt; γ₁ − β
        /// and c̃' = SHAKE-256(μ ‖ w1Encode(w'1), λ/4) equals c̃ from the signature.
        /// </summary>
        public bool VerifyInternal(byte[] pk, BitArray mPrim, byte[] sigma)
        {
            var (rho, t1) = _encoder.PkDecode(pk);
            SignatureDto dto = _encoder.SigDecode(sigma);

            if (dto.H == null)
            {
                return false;
            }

            byte[] tr = Shake256.HashData(pk, 64);
            byte[] mi = CalcMi(mPrim, tr);
            int[][][] aHat = _pseudoRandomSampler.ExpandA(rho);

            int[] c = _pseudoRandomSampler.SampleInBall(dto.CWave);
            int[][] az = _nttArithmetic.MatrixVectorNtt(aHat, Ntt.ForwardNtt(dto.Z));

            int[][] aproxedWPrim = CalcApproximatedW1Prim(t1, c, az);
            int[][] wPrim = _dilithiumFunctions.UseHint(dto.H, aproxedWPrim);
            byte[] cWavePrim = CalcCWave(mi, wPrim);
            int zInfiniteNorm = PolynomialNorm.InfinityNorm(dto.Z, DilithiumParameters.Q);

            return zInfiniteNorm < _parameters.Gamma1 - _parameters.Beta
                && cWavePrim.SequenceEqual(dto.CWave);
        }

        /// <summary>
        /// Computes μ = SHAKE-256(tr ‖ M', 64), where tr is the public-key hash
        /// and M' is the padded message bit-string.
        /// </summary>
        private byte[] CalcMi(BitArray mPrim, byte[] tr)
        {
            BitArray trBits = new BitArray(tr);
            BitArray hashContentBits = BitArrayHelpers.Concat(trBits, mPrim);
            byte[] hashContent = _bitAlgorithms.BitsToBytes(hashContentBits);
            byte[] mi = Shake256.HashData(hashContent, 64);

            return mi;
        }

        /// <summary>
        /// Computes the approximation w' = NTT⁻¹(Az − c·NTT(t1·2^d)) used as input to UseHint.
        /// Delegates scaling of t1 by 2^d and its NTT to <see cref="CalcT1"/>.
        /// </summary>
        private int[][] CalcApproximatedW1Prim(int[][] t1, int[] c, int[][] az) =>
            Ntt.InverseNtt(
                _nttArithmetic.SubtractVectorNtt(
                    az.Length,
                    az,
                    _nttArithmetic.ScalarVectorNtt(t1.Length, Ntt.ForwardNtt(c), CalcT1(t1))
                )
            );

        /// <summary>
        /// Scales each t1 coefficient by 2^d (left shift by d bits) and returns the result
        /// in NTT domain. Reconstructs the high part of the public key commitment t·2^d = t1·2^d + t0.
        /// </summary>
        private int[][] CalcT1(int[][] t1)
        {
            int[][] res = new int[t1.Length][];

            for (int i = 0; i < t1.Length; i++)
            {
                res[i] = new int[t1[i].Length];

                for (int j = 0; j < t1[i].Length; j++)
                {
                    res[i][j] = t1[i][j] << _parameters.D;
                }
            }

            return Ntt.ForwardNtt(res);
        }

        /// <summary>
        /// Computes c̃' = SHAKE-256(μ ‖ w1Encode(w'1), λ/4) to be compared against
        /// the challenge hash c̃ extracted from the signature.
        /// </summary>
        private byte[] CalcCWave(byte[] mi, int[][] wPrim) =>
            Shake256.HashData(
                ByteArrayHelpers.ConcatBytes(mi, _encoder.W1Encode(wPrim)),
                _parameters.Lambda / 4
            );
    }
}
