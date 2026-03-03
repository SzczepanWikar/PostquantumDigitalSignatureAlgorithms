using System.Security.Cryptography;
using Core.Helpers;

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

        public byte[] F(byte[] pkSeed, byte[] adrs, byte[] m1) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs, m1), _n);

        public byte[] H(byte[] pkSeed, byte[] adrs, byte[] m2) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs, m2), _n);

        public byte[] HMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] m) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(r, pkSeed, pkRoot, m), _m);

        public byte[] Prf(byte[] pkSeed, byte[] skSeed, byte[] adrs) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs, skSeed), _n);

        public byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] m) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(skPrf, optRand, m), _n);

        public byte[] T(byte[] pkSeed, byte[] adrs, byte[] ml) =>
            Shake256.HashData(ByteArrayHelpers.ConcatBytes(pkSeed, adrs, ml), _n);
    }
}
