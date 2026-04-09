using System.Diagnostics;

namespace SphincsPlus.Algorithms
{
    internal static class ByteConversions
    {
        public static int ToInt(byte[] x) => ToInt(x, x.Length);
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
        
        public static ulong ToUint64(byte[] x) => ToUint64(x, x.Length);
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
