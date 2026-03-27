using Core.Helpers;

namespace SphincsPlus.Models
{
    public sealed record SecretKey(byte[] SkSeed, byte[] SkPrf, byte[] PkSeed, byte[] PkRoot)
    {
        public byte[] ToBytesArray() => ByteArrayHelpers.ConcatBytes(SkSeed, SkPrf, PkSeed, PkRoot);

        public static SecretKey FromBytesArray(byte[] bytes)
        {
            int n = bytes.Length / 4;
            var skSeed = new byte[n];
            var skPrf = new byte[n];
            var pkSeed = new byte[n];
            var pkRoot = new byte[n];
            Buffer.BlockCopy(bytes, 0, skSeed, 0, n);
            Buffer.BlockCopy(bytes, n, skPrf, 0, n);
            Buffer.BlockCopy(bytes, 2 * n, pkSeed, 0, n);
            Buffer.BlockCopy(bytes, 3 * n, pkRoot, 0, n);
            return new SecretKey(skSeed, skPrf, pkSeed, pkRoot);
        }
    }
}
