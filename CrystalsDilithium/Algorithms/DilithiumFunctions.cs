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

        /// <summary>
        /// Algorithm 35 — Power2Round (polynomial vector variant). Applies
        /// <see cref="Power2Round(int)"/> coefficient-wise to each polynomial in the matrix
        /// <paramref name="r"/> and returns the pair of result matrices (r1, r0).
        /// </summary>
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

        /// <summary>
        /// Algorithm 35 — Power2Round. Decomposes <paramref name="r"/> mod q into a high part r1
        /// and a low part r0 ∈ (−2^d/2, 2^d/2] such that r ≡ r1·2^d + r0 (mod q).
        /// </summary>
        public (int r1, int r0) Power2Round(int r)
        {
            r = r % DilithiumParameters.Q;

            int TwoToPowerOfD = 1 << _parameters.D;

            int r0 = Modulo.ModPlusMinus(r, TwoToPowerOfD);
            int r1 = (r - r0) / TwoToPowerOfD;

            return (r1, r0);
        }

        /// <summary>
        /// Algorithm 36 — Decompose (polynomial matrix variant). Applies
        /// <see cref="Decompose(int)"/> coefficient-wise to each polynomial in the matrix
        /// <paramref name="r"/> and returns the pair of result matrices (r1, r0).
        /// </summary>
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

        /// <summary>
        /// Algorithm 36 — Decompose (polynomial variant). Applies
        /// <see cref="Decompose(int)"/> coefficient-wise to polynomial <paramref name="r"/>
        /// and returns the pair of result polynomials (r1, r0).
        /// </summary>
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

        /// <summary>
        /// Algorithm 36 — Decompose. Decomposes <paramref name="r"/> mod q into a high part r1
        /// and a low part r0 ∈ (−γ₂, γ₂] such that r ≡ r1·2γ₂ + r0 (mod q), using α = 2γ₂.
        /// When r − r0 = q − 1, returns (0, r0 − 1) to avoid r1 = (q−1)/(2γ₂).
        /// </summary>
        public (int r1, int r0) Decompose(int r) => Decompose(r, 2 * _parameters.Gamma2);

        /// <summary>
        /// Algorithm 36 — Decompose (explicit α). Decomposes <paramref name="r"/> mod q using
        /// the provided <paramref name="alpha"/> divisor instead of the default 2γ₂.
        /// </summary>
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

        /// <summary>
        /// Algorithm 37 — HighBits (polynomial matrix variant). Returns the high parts r1
        /// of <see cref="Decompose(int)"/> applied coefficient-wise to each polynomial in
        /// <paramref name="r"/>.
        /// </summary>
        public int[][] HighBits(int[][] r)
        {
            int[][] res = new int[r.Length][];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = HighBits(r[i]);
            }

            return res;
        }

        /// <summary>
        /// Algorithm 37 — HighBits (polynomial variant). Returns the high parts r1 of
        /// <see cref="Decompose(int)"/> applied coefficient-wise to polynomial <paramref name="r"/>.
        /// </summary>
        public int[] HighBits(int[] r)
        {
            int[] res = new int[r.Length];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = HighBits(r[i]);
            }

            return res;
        }

        /// <summary>
        /// Algorithm 37 — HighBits. Returns the high part r1 of <see cref="Decompose(int)"/>
        /// for the coefficient <paramref name="r"/>.
        /// </summary>
        public int HighBits(int r) => Decompose(r).r1;

        /// <summary>
        /// Algorithm 38 — LowBits (polynomial matrix variant). Returns the low parts r0
        /// of <see cref="Decompose(int)"/> applied coefficient-wise to each polynomial in
        /// <paramref name="r"/>.
        /// </summary>
        public int[][] LowBits(int[][] r)
        {
            int[][] res = new int[r.Length][];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = LowBits(r[i]);
            }

            return res;
        }

        /// <summary>
        /// Algorithm 38 — LowBits (polynomial variant). Returns the low parts r0 of
        /// <see cref="Decompose(int)"/> applied coefficient-wise to polynomial <paramref name="r"/>.
        /// </summary>
        public int[] LowBits(int[] r)
        {
            int[] res = new int[r.Length];

            for (int i = 0; i < r.Length; i++)
            {
                res[i] = LowBits(r[i]);
            }

            return res;
        }

        /// <summary>
        /// Algorithm 38 — LowBits. Returns the low part r0 of <see cref="Decompose(int)"/>
        /// for the coefficient <paramref name="r"/>.
        /// </summary>
        public int LowBits(int r) => Decompose(r).r0;

        /// <summary>
        /// Algorithm 39 — MakeHint (polynomial vector variant). Applies
        /// <see cref="MakeHint(int, int)"/> coefficient-wise across the polynomial vectors
        /// <paramref name="z"/> and <paramref name="r"/> and returns the hint vector.
        /// </summary>
        public BitArray[] MakeHint(int[][] z, int[][] r)
        {
            BitArray[] res = new BitArray[z.Length];
            for (int i = 0; i < z.Length; i++)
            {
                res[i] = MakeHint(z[i], r[i]);
            }
            return res;
        }

        /// <summary>
        /// Algorithm 39 — MakeHint (polynomial variant). Applies
        /// <see cref="MakeHint(int, int)"/> coefficient-wise to polynomials
        /// <paramref name="z"/> and <paramref name="r"/> and returns the hint polynomial.
        /// </summary>
        public BitArray MakeHint(int[] z, int[] r)
        {
            BitArray res = new(z.Length);
            for (int i = 0; i < z.Length; i++)
            {
                res[i] = MakeHint(z[i], r[i]);
            }
            return res;
        }

        /// <summary>
        /// Algorithm 39 — MakeHint. Returns 1 if the low-order bits of <paramref name="r"/>
        /// affect the high-order bits of r + <paramref name="z"/>, i.e. HighBits(r) ≠ HighBits(r + z).
        /// </summary>
        public bool MakeHint(int z, int r)
        {
            int r1 = HighBits(r);
            int v1 = HighBits(r + z);

            return r1 != v1;
        }

        /// <summary>
        /// Algorithm 40 — UseHint (polynomial vector variant). Applies
        /// <see cref="UseHint(bool, int)"/> coefficient-wise across the hint vector
        /// <paramref name="h"/> and the polynomial vector <paramref name="r"/>.
        /// </summary>
        public int[][] UseHint(BitArray[] h, int[][] r)
        {
            int[][] res = new int[r.Length][];
            for (int i = 0; i < r.Length; i++)
            {
                res[i] = UseHint(h[i], r[i]);
            }
            return res;
        }

        /// <summary>
        /// Algorithm 40 — UseHint (polynomial variant). Applies
        /// <see cref="UseHint(bool, int)"/> coefficient-wise to the hint polynomial
        /// <paramref name="h"/> and polynomial <paramref name="r"/>.
        /// </summary>
        public int[] UseHint(BitArray h, int[] r)
        {
            int[] res = new int[r.Length];
            for (int i = 0; i < r.Length; i++)
            {
                res[i] = UseHint(h[i], r[i]);
            }
            return res;
        }

        /// <summary>
        /// Algorithm 40 — UseHint. Uses hint bit <paramref name="h"/> to recover the high-order
        /// bits of r + z from <paramref name="r"/> alone. If h = 0 returns HighBits(r); otherwise
        /// adjusts r1 by ±1 mod m (where m = (q−1)/(2γ₂)) based on the sign of the low part r0.
        /// </summary>
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
