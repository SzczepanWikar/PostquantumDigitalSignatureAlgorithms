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

        public int[] SampleInBall(byte[] rho)
        {
            int[] c = new int[256];
            Array.Fill(c, 0);

            using Shake256 shake256 = new();
            shake256.AppendData(rho);

            byte[] hash = shake256.Read(8);
            BitArray h = new BitArray(hash);

            for (int i = 256 - _parameters.Tau; i < 256; i++)
            {
                int j = shake256.Read(1)[0];

                while (j > i)
                {
                    j = shake256.Read(1)[0];
                }

                c[i] = c[j];
                c[j] = h[i + _parameters.Tau - 256] ? -1 : 1;
            }

            return c;
        }

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

        public int[][] ExpandMask(byte[] rho, int mi)
        {
            Debug.Assert(mi >= 0, "Mask index must be non negative.");

            int[][] y = new int[_parameters.AMatrixDimensions.L][];
            int c = 1 + BitLength.GetNumberBitLength(_parameters.Gamma1 - 1);

            for (int r = 0; r < _parameters.AMatrixDimensions.L; r++)
            {
                byte[] rhoPrim = ByteArrayHelpers.ConcatBytes(
                    rho,
                    _bitAlgorithms.IntegerToBytes(mi +  r, 2)
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
