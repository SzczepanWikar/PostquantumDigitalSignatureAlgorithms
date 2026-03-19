using Core.Helpers;
using SphincsPlus.Hashing;

namespace SphincsPlus.Algorithms
{
    internal sealed class WotsPlus
    {
        private const byte _lgw = 4;
        private const byte _w = 16;
        private int _len1 => 2 * _parameters.N;
        private const byte _len2 = 3;
        private int _len => 2 * _parameters.N + 3;

        private readonly SphincsPlusParameters _parameters;
        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public WotsPlus(SphincsPlusParameters parameters)
        {
            _parameters = parameters;
        }
        public byte[] Chain(byte[] x, int i, int s, byte[] pkSeed, Adrs adrs)
        {
            byte[] tmp = new byte[x.Length];

            x.CopyTo(tmp, 0);

            for(int j = i; j < i+s; j++)
            {
                adrs.SetHashAddress(j);

                tmp = _hashing.F(pkSeed, adrs, tmp);
            }

            return tmp;
        }

        public byte[] PkGen(byte[] skSeed, byte[] pkSeed, Adrs address)
        {
            Adrs skAdrs = new Adrs(address);
            skAdrs.SetTypeAndClear((int)SphincsPlusConstants.WotsPrf);
            skAdrs.SetKeyPairAddress(address.GetKeyPairAddress());

            byte[][] tmp = new byte[_parameters.Len][];

            for (int i = 0; i < _parameters.Len; i++) 
            {
                skAdrs.SetChainAddress(i);
                byte[] sk = _hashing.Prf(pkSeed, skSeed, skAdrs);
                address.SetChainAddress(i);
                tmp[i] = Chain(sk, 0, _w - 1, pkSeed, address);
            }

            Adrs wotsPkAdrs = new Adrs(address);
            wotsPkAdrs.SetTypeAndClear((int)SphincsPlusConstants.WotsPk);
            wotsPkAdrs.SetKeyPairAddress(address.GetKeyPairAddress());

            byte[] pk = _hashing.T(pkSeed, wotsPkAdrs, ByteArrayHelpers.ConcatBytes(tmp));

            return pk;
        }
    }
}
