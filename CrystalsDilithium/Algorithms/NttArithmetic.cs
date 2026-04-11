using Core.Helpers;

namespace CrystalsDilithium.Algorithms
{
    internal sealed class NttArithmetic
    {
        private readonly DilithiumParameters _parameters;
        private readonly RingArithmetic _ringArithmetic = new(DilithiumParameters.Q);

        public NttArithmetic(DilithiumParameters parameters) => _parameters = parameters;

        /// <summary>
        /// Coefficient-wise addition of two NTT-domain polynomials:
        /// ĉ[i] = (â[i] + b̂[i]) mod q for i = 0, …, 255.
        /// </summary>
        public int[] AddNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < cHat.Length; i++)
            {
                cHat[i] = _ringArithmetic.Add(aHat[i], bHat[i]); // aHat[i] + bHat[i];
            }

            return cHat;
        }

        /// <summary>
        /// Coefficient-wise subtraction of two NTT-domain polynomials:
        /// ĉ[i] = (â[i] − b̂[i]) mod q for i = 0, …, 255.
        /// </summary>
        public int[] SubtractNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < cHat.Length; i++)
            {
                cHat[i] = _ringArithmetic.Subtract(aHat[i], bHat[i]);
            }

            return cHat;
        }

        /// <summary>
        /// Coefficient-wise negation of an NTT-domain polynomial:
        /// ĉ[i] = (−â[i]) mod q for i = 0, …, 255.
        /// </summary>
        public int[] ReverseNtt(int[] aHat)
        {
            int[] cHat = new int[aHat.Length];

            for (int i = 0; i < cHat.Length; i++)
            {
                cHat[i] = _ringArithmetic.Subtract(0, aHat[i]);
            }

            return cHat;
        }

        /// <summary>
        /// Coefficient-wise multiplication of two NTT-domain polynomials (Algorithm 43 — MultiplyNTTs):
        /// ĉ[i] = (â[i] · b̂[i]) mod q for i = 0, …, 255.
        /// Corresponds to polynomial multiplication modulo (X^256 + 1) in the standard domain.
        /// </summary>
        public int[] MultiplyNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < 256; i++)
            {
                cHat[i] = _ringArithmetic.Multiply(aHat[i], bHat[i]); // aHat[i] * bHat[i];
            }

            return cHat;
        }

        /// <summary>
        /// Coefficient-wise addition of two NTT-domain polynomial vectors of length
        /// <paramref name="l"/>. Applies <see cref="AddNtt"/> to each pair of polynomials.
        /// </summary>
        public int[][] AddVectorNtt(int l, int[][] aHat, int[][] bHat)
        {
            int[][] uHat = new int[l][];

            for (int i = 0; i < l; i++)
            {
                uHat[i] = AddNtt(aHat[i], bHat[i]);
            }

            return uHat;
        }

        /// <summary>
        /// Coefficient-wise subtraction of two NTT-domain polynomial vectors of length
        /// <paramref name="l"/>. Applies <see cref="SubtractNtt"/> to each pair of polynomials.
        /// </summary>
        public int[][] SubtractVectorNtt(int l, int[][] aHat, int[][] bHat)
        {
            int[][] uHat = new int[l][];

            for (int i = 0; i < l; i++)
            {
                uHat[i] = SubtractNtt(aHat[i], bHat[i]);
            }

            return uHat;
        }

        /// <summary>
        /// Coefficient-wise negation of an NTT-domain polynomial vector.
        /// Applies <see cref="ReverseNtt"/> to each polynomial in <paramref name="aHat"/>.
        /// </summary>
        public int[][] ReverseVectorNtt(int[][] aHat)
        {
            int[][] uHat = new int[aHat.Length][];

            for (int i = 0; i < aHat.Length; i++)
            {
                uHat[i] = ReverseNtt(aHat[i]);
            }

            return uHat;
        }

        /// <summary>
        /// Multiplies each polynomial in the NTT-domain vector <paramref name="vHat"/> by the
        /// scalar NTT-domain polynomial <paramref name="cHat"/> using <see cref="MultiplyNtt"/>.
        /// Computes ŵ[i] = ĉ ⊙ v̂[i] for i = 0, …, <paramref name="l"/>−1.
        /// </summary>
        public int[][] ScalarVectorNtt(int l, int[] cHat, int[][] vHat)
        {
            int[][] wHat = new int[l][];

            for (int i = 0; i < l; i++)
            {
                wHat[i] = MultiplyNtt(cHat, vHat[i]);
            }

            return wHat;
        }

        /// <summary>
        /// Algorithm 44 — MatVecMulNTT. Multiplies the k×l NTT-domain matrix <paramref name="mHat"/>
        /// by the NTT-domain vector <paramref name="vHat"/> of length l:
        /// ŵ[i] = Σ_{j=0}^{l−1} m̂[i][j] ⊙ v̂[j] (mod q) for i = 0, …, k−1,
        /// where ⊙ denotes coefficient-wise multiplication.
        /// </summary>
        public int[][] MatrixVectorNtt(int[][][] mHat, int[][] vHat)
        {
            int[][] wHat = new int[_parameters.AMatrixDimensions.K][];

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                wHat[i] = new int[256];

                for (int j = 0; j < _parameters.AMatrixDimensions.L; j++)
                {
                    for (int k = 0; k < 256; k++)
                    {
                        wHat[i][k] = _ringArithmetic.Add(
                            wHat[i][k],
                            _ringArithmetic.Multiply(mHat[i][j][k], vHat[j][k])
                        );
                    }
                }
            }

            return wHat;
        }
    }
}
