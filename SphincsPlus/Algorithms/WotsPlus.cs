using Core.Helpers;
using SphincsPlus.Hashing;

namespace SphincsPlus.Algorithms
{
    internal sealed class WotsPlus
    {
        private const byte _len2 = 3;
        private const int _precalcedCsumLength = 2; // ⌈(_len2*_parameters.LogW)/8⌉

        private readonly int _len1;

        private readonly SphincsPlusParameters _parameters;
        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public WotsPlus(SphincsPlusParameters parameters)
        {
            _parameters = parameters;
            _len1 = 2 * _parameters.N;
        }

        public byte[] Chain(byte[] x, int i, int s, byte[] pkSeed, Adrs adrs)
        {
            byte[] tmp = new byte[x.Length];

            x.CopyTo(tmp, 0);

            for (int j = i; j < i + s; j++)
            {
                adrs.SetHashAddress(j);

                tmp = _hashing.F(pkSeed, adrs, tmp);
            }

            return tmp;
        }

        public byte[] PkGen(byte[] skSeed, byte[] pkSeed, Adrs address)
        {
            Adrs skAdrs = InitAdrs(address, SphincsPlusConstants.WotsPrf);

            byte[][] tmp = new byte[_parameters.Len][];

            for (int i = 0; i < _parameters.Len; i++)
            {
                skAdrs.SetChainAddress(i);
                byte[] sk = _hashing.Prf(pkSeed, skSeed, skAdrs);
                address.SetChainAddress(i);
                tmp[i] = Chain(sk, 0, _parameters.W - 1, pkSeed, address);
            }

            Adrs wotsPkAdrs = InitAdrs(address, SphincsPlusConstants.WotsPk);

            byte[] pk = _hashing.T(pkSeed, wotsPkAdrs, ByteArrayHelpers.ConcatBytes(tmp));

            return pk;
        }

        public byte[] Sign(byte[] m, byte[] skSeed, byte[] pkSeed, Adrs address)
        {
            int[] msg = CalcMessage(m);

            Adrs skAdrs = InitAdrs(address, SphincsPlusConstants.WotsPrf);

            byte[][] sig = new byte[_parameters.Len][];

            for (int i = 0; i < _parameters.Len; i++)
            {
                skAdrs.SetChainAddress(i);
                byte[] sk = _hashing.Prf(pkSeed, skSeed, skAdrs);
                address.SetChainAddress(i);
                sig[i] = Chain(sk, 0, msg[i], pkSeed, address);
            }

            byte[] signature = ByteArrayHelpers.ConcatBytes(sig);

            return signature;
        }

        public byte[] PkFromSig(byte[] sig, byte[] m, byte[] pkSeed, Adrs address)
        {
            int[] msg = CalcMessage(m);

            byte[][] tmp = new byte[_parameters.Len][];

            for (int i = 0; i < _parameters.Len; i++)
            {
                address.SetChainAddress(i);
                byte[] sigI = sig[(i * _parameters.N)..((i + 1) * _parameters.N)];
                tmp[i] = Chain(sigI, msg[i], _parameters.W - 1 - msg[i], pkSeed, address);
            }

            Adrs wotsPkAdrs = InitAdrs(address, SphincsPlusConstants.WotsPk);
            byte[] pk = _hashing.T(pkSeed, wotsPkAdrs, ByteArrayHelpers.ConcatBytes(tmp));

            return pk;
        }

        private static Adrs InitAdrs(Adrs adrs, SphincsPlusConstants constant)
        {
            Adrs result = new Adrs(adrs);
            result.SetTypeAndClear(constant);
            result.SetKeyPairAddress(adrs.GetKeyPairAddress());

            return result;
        }

        private int[] CalcMessage(byte[] m)
        {
            int csum = 0;
            int[] msg = ByteConversions.Base2b(m, _parameters.LogW, _len1);

            for (int i = 0; i < _len1; i++)
            {
                csum += _parameters.W - 1 - msg[i];
            }

            csum = csum << ((8 - ((_len2 * _parameters.LogW) % 8)) % 8);
            int[] csumbaseW = ByteConversions.Base2b(
                ByteConversions.ToByte(csum, _precalcedCsumLength),
                _parameters.LogW,
                _len2
            );

            msg = msg.Concat(csumbaseW).ToArray();
            return msg;
        }
    }
}
