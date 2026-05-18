using System.Security.Cryptography;
using Core.Helpers;
using SphincsPlus.ADRS;

namespace SphincsPlus.Hashing
{
    internal sealed class ShaLevelOneFacade : ISphincsPlusHashing
    {
        private readonly int _n;
        private readonly int _m;

        public ShaLevelOneFacade(int n, int m)
        {
            _n = n;
            _m = m;
        }

        public byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1) =>
            SHA256
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[64 - _n], adrs.Compress(), m1))
                .Take(_n)
                .ToArray();

        public byte[] H(byte[] pkSeed, Adrs adrs, byte[] m2) =>
            SHA256
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[64 - _n], adrs.Compress(), m2))
                .Take(_n)
                .ToArray();

        public byte[] HMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] m) =>
            Core.Helpers.Hashing.Mgf1Sha256HashData(
                ByteArrayHelpers.ConcatBytes(
                    r,
                    pkSeed,
                    SHA256.HashData(ByteArrayHelpers.ConcatBytes(r, pkSeed, pkRoot, m))
                ),
                _m
            );

        public byte[] Prf(byte[] pkSeed, byte[] skSeed, Adrs adrs) =>
            SHA256
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[64 - _n], adrs.Compress(), skSeed))
                .Take(_n)
                .ToArray();

        public byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] m) =>
            HMACSHA256.HashData(skPrf, ByteArrayHelpers.ConcatBytes(optRand, m)).Take(_n).ToArray();

        public byte[] T(byte[] pkSeed, Adrs adrs, byte[] ml) =>
            SHA256
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[64 - _n], adrs.Compress(), ml))
                .Take(_n)
                .ToArray();
    }
}
