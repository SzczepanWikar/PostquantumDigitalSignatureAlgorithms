namespace SphincsPlus.Models
{
    internal sealed record SecretKey(byte[] SkSeed, byte[] SkPrf, byte[] PkSeed, byte[] PkRoot);
}
