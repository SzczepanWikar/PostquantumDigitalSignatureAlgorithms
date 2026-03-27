using Core.Helpers;

namespace SphincsPlus.Models
{
    public sealed record PublicKey(byte[] PkSeed, byte[] PkRoot)
    {
        public byte[] ToBytesArray() => ByteArrayHelpers.ConcatBytes(PkSeed, PkRoot);

        public static PublicKey FromBytesArray(byte[] bytes)
        {
            int n = bytes.Length / 2;
            var pkSeed = new byte[n];
            var pkRoot = new byte[n];
            Buffer.BlockCopy(bytes, 0, pkSeed, 0, n);
            Buffer.BlockCopy(bytes, n, pkRoot, 0, n);
            return new PublicKey(pkSeed, pkRoot);
        }
    }
}
