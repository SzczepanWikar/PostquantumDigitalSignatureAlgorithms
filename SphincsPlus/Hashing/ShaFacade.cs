using System.Security.Cryptography;
using Core.Helpers;

namespace SphincsPlus.Hashing
{
    internal sealed class ShaFacade : ISphincsPlusHashing
    {
        private readonly int _n;
        private readonly int _m;

        public ShaFacade(int n, int m)
        {
            _n = n;
            _m = m;
        }

        public byte[] F(byte[] pkSeed, byte[] adrs, byte[] m1) =>
            SHA256
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[64 - _n], adrs, m1))
                .Take(_n)
                .ToArray();

        public byte[] H(byte[] pkSeed, byte[] adrs, byte[] m2) =>
            SHA512
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[128 - _n], adrs, m2))
                .Take(_n)
                .ToArray();

        public byte[] HMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] m) =>
            Core.Helpers.Hashing.Mgf1Sha512HashData(
                ByteArrayHelpers.ConcatBytes(
                    r,
                    pkSeed,
                    SHA512.HashData(ByteArrayHelpers.ConcatBytes(r, pkSeed, pkRoot, m))
                ),
                _m
            );

        public byte[] Prf(byte[] pkSeed, byte[] skSeed, byte[] adrs) =>
            SHA256
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[64 - _n], adrs, skSeed))
                .Take(_n)
                .ToArray();

        public byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] m) =>
            HMACSHA512.HashData(skPrf, ByteArrayHelpers.ConcatBytes(optRand, m)).Take(_n).ToArray();

        public byte[] T(byte[] pkSeed, byte[] adrs, byte[] ml) =>
            SHA512
                .HashData(ByteArrayHelpers.ConcatBytes(pkSeed, new byte[128 - _n], adrs, ml))
                .Take(_n)
                .ToArray();
    }
}
