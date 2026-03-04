using System.Diagnostics;

namespace SphincsPlus
{
    internal static class ByteConversions
    {
        public static long ToInt64(byte[] x)
        {
            long total = 0;

            for (int i = 0; i < x.Length; i++) 
            {
                total = 256L * total + x[i];
            }

            return total;
        }

        public static byte[] ToByte(int x, int n)
        {
            Debug.Assert(x >= 0, "x must be nonnegative.");

            int total = x;
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
            int @in = 0, bits = 0, total = 0;
            int[] baseb = new int[outLen];

            for (int @out = 0; @out < outLen; @out++)
            {
                while(bits < b)
                {
                    total = (total << 8) + x[@in];
                    @in++;
                    bits += 8;
                }

                bits -= b;
                baseb[@out] = (total >> bits) % (1 << b);
            }

            return baseb;
        }
    }
}
