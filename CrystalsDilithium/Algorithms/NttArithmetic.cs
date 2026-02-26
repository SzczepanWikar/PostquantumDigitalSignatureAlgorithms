using Core.Helpers;

namespace CrystalsDilithium.Algorithms
{
    internal sealed class NttArithmetic
    {
        private readonly DilithiumParameters _parameters;
        private readonly RingArithmetic _ringArithmetic = new(DilithiumParameters.Q);

        public NttArithmetic(DilithiumParameters parameters) => _parameters = parameters;

        public int[] AddNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < cHat.Length; i++)
            {
                cHat[i] = _ringArithmetic.Add(aHat[i], bHat[i]); // aHat[i] + bHat[i];
            }

            return cHat;
        }

        public int[] SubtractNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < cHat.Length; i++)
            {
                cHat[i] = _ringArithmetic.Subtract(aHat[i], bHat[i]);
            }

            return cHat;
        }

        public int[] ReverseNtt(int[] aHat)
        {
            int[] cHat = new int[aHat.Length];

            for (int i = 0; i < cHat.Length; i++)
            {
                cHat[i] = _ringArithmetic.Subtract(0, aHat[i]);
            }

            return cHat;
        }

        public int[] MultiplyNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < 256; i++)
            {
                cHat[i] = _ringArithmetic.Multiply(aHat[i], bHat[i]); // aHat[i] * bHat[i];
            }

            return cHat;
        }

        public int[][] AddVectorNtt(int l, int[][] aHat, int[][] bHat)
        {
            int[][] uHat = new int[l][];

            for (int i = 0; i < l; i++)
            {
                uHat[i] = AddNtt(aHat[i], bHat[i]);
            }

            return uHat;
        }

        public int[][] SubtractVectorNtt(int l, int[][] aHat, int[][] bHat)
        {
            int[][] uHat = new int[l][];

            for (int i = 0; i < l; i++)
            {
                uHat[i] = SubtractNtt(aHat[i], bHat[i]);
            }

            return uHat;
        }

        public int[][] ReverseVectorNtt(int[][] aHat)
        {
            int[][] uHat = new int[aHat.Length][];

            for (int i = 0; i < aHat.Length; i++)
            {
                uHat[i] = ReverseNtt(aHat[i]);
            }

            return uHat;
        }

        public int[][] ScalarVectorNtt(int l, int[] cHat, int[][] vHat)
        {
            int[][] wHat = new int[l][];

            for (int i = 0; i < l; i++)
            {
                wHat[i] = MultiplyNtt(cHat, vHat[i]);
            }

            return wHat;
        }

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
