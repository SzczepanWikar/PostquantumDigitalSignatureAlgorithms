namespace CrystalsDilithium.Algorithms
{
    internal sealed class NttArithmetic
    {
        private readonly DilithiumParameters _parameters;

        public NttArithmetic(DilithiumParameters parameters) => _parameters = parameters;

        public int[] AddNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < 256; i++)
            {
                cHat[i] = aHat[i] + bHat[i];
            }

            return cHat;
        }

        public int[] MultiplyNtt(int[] aHat, int[] bHat)
        {
            int[] cHat = new int[256];

            for (int i = 0; i < 256; i++)
            {
                cHat[i] = aHat[i] * bHat[i];
            }

            return cHat;
        }

        public int[][] AddVectorNtt(int[][] aHat, int[][] bHat)
        {
            int[][] uHat = new int[_parameters.AMatrixDimensions.L][];

            for (int i = 0; i < _parameters.AMatrixDimensions.L; i++)
            {
                uHat[i] = AddNtt(aHat[i], bHat[i]);
            }

            return uHat;
        }

        public int[][] ScalarVectorNtt(int[] cHat, int[][] vHat)
        {
            int[][] wHat = new int[_parameters.AMatrixDimensions.L][];

            for (int i = 0; i < _parameters.AMatrixDimensions.L; i++)
            {
                wHat[i] = MultiplyNtt(cHat, vHat[i]);
            }

            return wHat;
        }

        public int[][] MatrixVectorNtt(int[][][] MHat, int[][] vHat)
        {
            int[][] wHat = new int[_parameters.AMatrixDimensions.K][];

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                for (int j = 0; j < _parameters.AMatrixDimensions.L; j++)
                {
                    wHat[i] = AddNtt(wHat[i], MultiplyNtt(MHat[i][j], vHat[j]));
                }
            }

            return wHat;
        }
    }
}
