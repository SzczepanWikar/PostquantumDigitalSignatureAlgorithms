namespace Core.Helpers
{
    public sealed class RingArithmetic
    {
        public int Modulus { get; }

        public RingArithmetic(int modulus)
        {
            if (modulus <= 1)
                throw new ArgumentOutOfRangeException(nameof(modulus));

            Modulus = modulus;
        }

        /// <summary>
        /// (a + b) mod q
        /// </summary>
        public int Add(int a, int b)
        {
            int r = a + b;

            if (r < 0 || r >= Modulus)
                r %= Modulus;

            return r < 0 ? r + Modulus : r;
        }

        /// <summary>
        /// (a - b) mod q
        /// </summary>
        public int Subtract(int a, int b)
        {
            int r = a - b;

            if (r < 0 || r >= Modulus)
                r %= Modulus;

            return r < 0 ? r + Modulus : r;
        }

        /// <summary>
        /// (a * b) mod q
        /// </summary>
        public int Multiply(int a, int b)
        {
            long r = (long)a * b; // unikamy overflow
            r %= Modulus;
            return (int)(r < 0 ? r + Modulus : r);
        }
    }
}
