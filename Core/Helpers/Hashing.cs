using System.Security.Cryptography;

namespace Core.Helpers
{
    public static class Hashing
    {
        public static byte[] Mgf1Sha256HashData(byte[] seed, int maskLen)
        {
            const int hLen = 32;

            int iterations = (int)Math.Ceiling((double)maskLen / hLen);
            byte[] t = new byte[iterations * hLen];

            for (int i = 0; i < iterations; i++)
            {
                byte[] input = new byte[seed.Length + 4];
                Buffer.BlockCopy(seed, 0, input, 0, seed.Length);
                input[seed.Length] = (byte)(i >> 24);
                input[seed.Length + 1] = (byte)(i >> 16);
                input[seed.Length + 2] = (byte)(i >> 8);
                input[seed.Length + 3] = (byte)i;

                byte[] hash = SHA256.HashData(input);
                Buffer.BlockCopy(hash, 0, t, i * hLen, hLen);
            }

            return t[..maskLen];
        }
    }
}
