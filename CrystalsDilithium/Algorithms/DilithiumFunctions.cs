using System.Collections;
using System.Security.Cryptography;
using Core.Helpers;

namespace CrystalsDilithium.Algorithms
{
    internal sealed class DilithiumFunctions
    {
        private readonly DilithiumParameters _parameters;
        private readonly int _m;

        public DilithiumFunctions(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _m = (DilithiumParameters.Q - 1) / (2 * _parameters.Gamma2);
        }

        public (int[][] r1, int[][] r0) Power2Round(int[][] r)
        {
            int[][] r1 = new int[r.Length][];
            int[][] r0 = new int[r.Length][];

            for (int i = 0; i < r.Length; i++)
            {
                if (r[i].Length != 256)
                    throw new CryptographicException("Invalid polynomial length");

                r1[i] = new int[r[i].Length];
                r0[i] = new int[r[i].Length];

                for (int j = 0; j < r[i].Length; j++)
                {
                    (r1[i][j], r0[i][j]) = Power2Round(r[i][j]);
                }
            }

            return (r1, r0);
        }

        public (int r1, int r0) Power2Round(int r)
        {
            r = r % DilithiumParameters.Q;

            int TwoToPowerOfD = 1 << _parameters.D;

            int r0 = Modulo.ModPlusMinus(r, TwoToPowerOfD);
            int r1 = (r - r0) / TwoToPowerOfD;

            return (r1, r0);
        }

        public (int[][] r1, int[][] r0) Decompose(int[][] r)
        {
            int[][] r1 = new int[r.Length][];
            int[][] r0 = new int[r.Length][];

            for (int i = 0; i < r.Length; i++)
            {
                (r1[i], r0[i]) = Decompose(r[i]);
            }

            return (r1, r0);
        }

        public (int[] r1, int[] r0) Decompose(int[] r)
        {
            int[] r1 = new int[r.Length];
            int[] r0 = new int[r.Length];

            for (int i = 0; i < r.Length; i++)
            {
                (r1[i], r0[i]) = Decompose(r[i]);
            }

            return (r1, r0);
        }

        public (int r1, int r0) Decompose(int r) => Decompose(r, 2 * _parameters.Gamma2);

        public (int r1, int r0) Decompose(int r, int alpha)
        {
            if (r < 0)
            {
                throw new CryptographicException($"Decompose input must be non-negative, got {r}.");
            }

            r = r % DilithiumParameters.Q;

            int r0 = Modulo.ModPlusMinus(r, alpha);

            if (r - r0 == DilithiumParameters.Q - 1)
            {
                return (0, r0 - 1);
            }

            int r1 = (r - r0) / alpha;

            return (r1, r0);
        }

        public int[][] HighBits(int[][] r)
        {
            int[][] res = new int[r.Length][];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = HighBits(r[i]);
            }

            return res;
        }

        public int[] HighBits(int[] r)
        {
            int[] res = new int[r.Length];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = HighBits(r[i]);
            }

            return res;
        }

        public int HighBits(int r) => Decompose(r).r1;

        public int[][] LowBits(int[][] r)
        {
            int[][] res = new int[r.Length][];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = LowBits(r[i]);
            }

            return res;
        }

        public int[] LowBits(int[] r)
        {
            int[] res = new int[r.Length];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = LowBits(r[i]);
            }

            return res;
        }

        public int LowBits(int r) => Decompose(r).r0;

        public BitArray[] MakeHint(int[][] z, int[][] r)
        {
            BitArray[] res = new BitArray[z.Length];
            for (int i = 0; i < z.Length; i++)
            {
                res[i] = MakeHint(z[i], r[i]);
            }
            return res;
        }

        public BitArray MakeHint(int[] z, int[] r)
        {
            BitArray res = new(z.Length);
            for (int i = 0; i < z.Length; i++)
            {
                res[i] = MakeHint(z[i], r[i]);
            }
            return res;
        }

        public bool MakeHint(int z, int r)
        {
            int r1 = HighBits(r);
            int v1 = HighBits(r + z);

            return r1 != v1;
        }

        public int[][] UseHint(BitArray[] h, int[][] r)
        {
            int[][] res = new int[r.Length][];
            for (int i = 0; i < r.Length; i++)
            {
                res[i] = UseHint(h[i], r[i]);
            }
            return res;
        }

        public int[] UseHint(BitArray h, int[] r)
        {
            int[] res = new int[r.Length];
            for (int i = 0; i < r.Length; i++)
            {
                res[i] = UseHint(h[i], r[i]);
            }
            return res;
        }

        public int UseHint(bool h, int r)
        {
            (int r1, int r0) = Decompose(r);

            if (!h)
            {
                return r1;
            }

            if (r0 > 0)
            {
                return (r1 + 1) % _m;
            }

            return Modulo.FloorMod(r1 - 1, _m);
        }
    }
}
