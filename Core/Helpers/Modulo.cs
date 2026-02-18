namespace Core.Helpers
{
    public static class Modulo
    {

        /// <summary>
        /// Math modulo (floor division): result always ∈ [0, m−1].
        /// </summary>
        public static int FloorMod(int n, int m)
        {
            int r = n % m;
            return r < 0 ? r + m : r;
        }

        /// <summary>
        /// Math modulo (floor division): result always ∈ [0, m−1].
        /// </summary>
        public static int FloorMod(long n, int m)
        {
            int r = (int)(n % m);
            return r < 0 ? r + m : r;
        }

        /// <summary>
        /// Modulo in centered ring arithmetic
        /// </summary>
        /// <param name="n"></param>
        /// <param name="m"></param>
        /// <returns></returns>
        public static int ModPlusMinus(int n, int m)
        {
            int mod;

            if ((m & (m - 1)) == 0)
            {
                mod = n & (m - 1);
            }
            else
            {
                mod = n % m;
                if (mod < 0)
                    mod += m;
            }

            if (mod > (m >> 1))
            {
                mod -= m;
            }

            return mod;
        }
    }
}