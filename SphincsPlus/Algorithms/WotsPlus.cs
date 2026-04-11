using Core.Helpers;
using SphincsPlus.Hashing;
using System.Diagnostics;

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

        /// <summary>
        /// Algorithm 4 — chain. Iterates the hash function F exactly <paramref name="s"/> times
        /// starting from index <paramref name="i"/>, producing the s-step chain value from input
        /// <paramref name="x"/>. Requires i + s ≤ w − 1.
        /// </summary>
        public byte[] Chain(byte[] x, int i, int s, byte[] pkSeed, Adrs adrs)
        {
            Debug.Assert((i + s) <= _parameters.W - 1);

            byte[] tmp = new byte[x.Length];

            x.CopyTo(tmp, 0);

            for (int j = i; j < i + s; j++)
            {
                adrs.SetHashAddress(j);

                tmp = _hashing.F(pkSeed, adrs, tmp);
            }

            return tmp;
        }

        /// <summary>
        /// Algorithm 5 — wots_pkGen. Generates the WOTS+ public key by computing len full chains
        /// (0 to w−1) from secret values derived via PRF, then compressing the chain ends with T_len.
        /// </summary>
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

        /// <summary>
        /// Algorithm 6 — wots_sign. Produces a WOTS+ signature of len·n bytes on message
        /// <paramref name="m"/>. Converts m to base-w via <see cref="CalcMessage"/> (including
        /// the checksum), then for each chain i advances the secret-key value msg[i] steps.
        /// </summary>
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

        /// <summary>
        /// Algorithm 7 — wots_pkFromSig. Recovers the WOTS+ public key from signature
        /// <paramref name="sig"/> and message <paramref name="m"/>. For each chain i continues
        /// from the signature value for the remaining w−1−msg[i] steps, then compresses the
        /// chain ends with T_len.
        /// </summary>
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

        /// <summary>
        /// Creates a copy of <paramref name="adrs"/>, sets its type to <paramref name="constant"/>,
        /// and restores the key-pair address. Used to derive WOTS_PRF and WOTS_PK addresses
        /// from the current WOTS_HASH address without mutating the original.
        /// </summary>
        private static Adrs InitAdrs(Adrs adrs, SphincsPlusConstants constant)
        {
            Adrs result = new Adrs(adrs);
            result.SetTypeAndClear(constant);
            result.SetKeyPairAddress(adrs.GetKeyPairAddress());

            return result;
        }

        /// <summary>
        /// Converts message <paramref name="m"/> to a len-element base-w array with appended
        /// checksum. Computes csum = Σ(w−1−msg[i]) over len1 digits, left-shifts to align to
        /// log₂(w)-bit boundaries, encodes as len2 base-w digits, and concatenates with msg.
        /// </summary>
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
