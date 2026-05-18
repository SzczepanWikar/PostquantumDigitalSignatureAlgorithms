using System.Security.Cryptography;
using Core.Helpers;
using SphincsPlus.ADRS;

namespace SphincsPlus.Hashing
{
    internal sealed class ShakeFacade : ISphincsPlusHashing
    {
        private readonly int _n;
        private readonly int _m;

        public ShakeFacade(int n, int m)
        {
            _n = n;
            _m = m;
        }

        public byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs.Content, m1), _n);

        public byte[] H(byte[] pkSeed, Adrs adrs, byte[] m2) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs.Content, m2), _n);

        public byte[] HMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] m) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(r, pkSeed, pkRoot, m), _m);

        public byte[] Prf(byte[] pkSeed, byte[] skSeed, Adrs adrs) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs.Content, skSeed), _n);

        public byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] m) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(skPrf, optRand, m), _n);

        public byte[] T(byte[] pkSeed, Adrs adrs, byte[] ml) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs.Content, ml), _n);
    }
}
