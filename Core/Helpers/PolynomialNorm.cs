namespace Core.Helpers
{
    public static class PolynomialNorm
    {
        /// <summary>
        /// ||poly||∞ = max |coeff| over all coefficients,
        /// where each coefficient is interpreted as a centered representative in (−q/2, q/2].
        /// Accepts coefficients in [0, q) or already-centered negative values.
        /// </summary>
        public static int InfinityNorm(int[] poly, int q)
        {
            int norm = 0;

            for (int i = 0; i < poly.Length; i++)
            {
                int abs = poly[i] >= 0 ? Math.Min(poly[i], q - poly[i]) : -poly[i];
                if (abs > norm)
                    norm = abs;
            }

            return norm;
        }

        /// <summary>
        /// ||v||∞ = max ||v[i]||∞ over all polynomials in the vector.
        /// </summary>
        public static int InfinityNorm(int[][] vector, int q)
        {
            int norm = 0;

            for (int i = 0; i < vector.Length; i++)
            {
                int polyNorm = InfinityNorm(vector[i], q);
                if (polyNorm > norm)
                    norm = polyNorm;
            }

            return norm;
        }
    }
}
