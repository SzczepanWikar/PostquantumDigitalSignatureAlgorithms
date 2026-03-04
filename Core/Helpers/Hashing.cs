using System.Security.Cryptography;

namespace Core.Helpers
{
    public static class Hashing
    {
        public static byte[] Mgf1Sha256HashData(byte[] seed, int maskLen) => Mgf1ShaHashData(seed, maskLen, 32, SHA256.HashData);
        public static byte[] Mgf1Sha512HashData(byte[] seed, int maskLen) => Mgf1ShaHashData(seed, maskLen, 64, SHA512.HashData);

        private static byte[] Mgf1ShaHashData(byte[] seed, int maskLen, int hLen, Func<byte[], byte[]> hashingFunction)
        {
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

                byte[] hash = hashingFunction(input);
                Buffer.BlockCopy(hash, 0, t, i * hLen, hLen);
            }

            return t[..maskLen];
        } 
    }
}
