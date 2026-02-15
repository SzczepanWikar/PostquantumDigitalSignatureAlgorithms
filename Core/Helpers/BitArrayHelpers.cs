using System.Collections;

namespace Core.Helpers
{
    public static class BitArrayHelpers
    {
        public static BitArray Concat(BitArray a, BitArray b)
        {
            BitArray result = new BitArray(a.Length + b.Length);

            for (int i = 0; i < a.Length; i++)
            {
                result[i] = a[i];
            }

            for (int i = 0; i < b.Length; i++)
            {
                result[a.Length + i] = b[i];
            }

            return result;
        }
    }
}
