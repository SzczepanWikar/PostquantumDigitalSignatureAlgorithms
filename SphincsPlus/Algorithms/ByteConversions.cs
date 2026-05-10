using System.Diagnostics;

namespace SphincsPlus.Algorithms
{
    internal static class ByteConversions
    {
        /// <summary>
        /// Algorithm 2 — toInt. Converts the full byte string <paramref name="x"/> to a
        /// non-negative integer. Delegates to <see cref="ToInt(byte[], int)"/>.
        /// </summary>
        public static int ToInt(byte[] x) => ToInt(x, x.Length);
        /// <summary>
        /// Algorithm 2 — toInt. Interprets the first <paramref name="n"/> bytes of
        /// <paramref name="x"/> as a big-endian unsigned integer:
        /// result = Σ_{i=0}^{n−1} x[i] · 256^(n−1−i).
        /// </summary>
        public static int ToInt(byte[] x, int n)
        {
            Debug.Assert(x.Length >= n);

            int total = 0;

            for (int i = 0; i < n; i++) 
            {
                total = 256 * total + x[i];
            }

            return total;
        }
        
        /// <summary>
        /// Algorithm 2 — toInt (ulong variant). Converts the full byte string <paramref name="x"/>
        /// to a <see langword="ulong"/>. Delegates to <see cref="ToUint64(byte[], int)"/>.
        /// </summary>
        public static ulong ToUint64(byte[] x) => ToUint64(x, x.Length);
        /// <summary>
        /// Algorithm 2 — toInt (ulong variant). Interprets the first <paramref name="n"/> bytes of
        /// <paramref name="x"/> as a big-endian unsigned integer returned as <see langword="ulong"/>.
        /// Used when the value exceeds <see cref="int"/> range (e.g. tree indices).
        /// </summary>
        public static ulong ToUint64(byte[] x, int n)
        {
            Debug.Assert(x.Length >= n);

            ulong total = 0;

            for (int i = 0; i < n; i++)
            {
                total = 256 * total + x[i];
            }

            return total;
        }

        /// <summary>
        /// Algorithm 3 — toByte. Converts non-negative integer <paramref name="x"/> to a
        /// big-endian byte string of length <paramref name="n"/>:
        /// s[n−1−i] = (x / 256^i) mod 256 for i = 0, …, n−1.
        /// </summary>
        public static byte[] ToByte(long x, int n)
        {
            Debug.Assert(x >= 0, "x must be nonnegative.");

            if (x == 0)
            {
                return new byte[n];
            }

            long total = x;
            byte[] s = new byte[n];

            for (int i = 0; i < n; i++)
            {
                s[n - 1 - i] = (byte)(total % 256);
                total = total >> 8;
            }

            return s;
        }

        /// <summary>
        /// Algorithm 3 — toByte (ulong variant). Converts non-negative integer <paramref name="x"/>
        /// to a big-endian byte string of length <paramref name="n"/>. Used when the value
        /// exceeds <see cref="long"/> range.
        /// </summary>
        public static byte[] ToByte(ulong x, int n)
        {
            Debug.Assert(x >= 0, "x must be nonnegative.");

            if (x == 0)
            {
                return new byte[n];
            }

            ulong total = x;
            byte[] s = new byte[n];

            for (int i = 0; i < n; i++)
            {
                s[n - 1 - i] = (byte)(total % 256);
                total = total >> 8;
            }

            return s;
        }

        /// <summary>
        /// Algorithm 4 — base_2b. Converts byte string <paramref name="x"/> to an array of
        /// <paramref name="outLen"/> integers, each representing a <paramref name="b"/>-bit
        /// chunk read in big-endian order: baseb[i] = ⌊X / 2^(b·(outLen−1−i))⌋ mod 2^b.
        /// Used to split WOTS+ chain indices from a hash output.
        /// </summary>
        public static int[] Base2b(byte[] x, int b, int outLen)
        {
            int @in = 0, bits = 0;
            long total = 0;
            int[] baseb = new int[outLen];

            for (int @out = 0; @out < outLen; @out++)
            {
                while (bits < b)
                {
                    total = (total << 8) | x[@in];
                    @in++;
                    bits += 8;
                }

                bits -= b;
                baseb[@out] = (int)((total >> bits) & ((1 << b) - 1));
                total &= (1L << bits) - 1;
            }

            return baseb;
        }
    }
}
