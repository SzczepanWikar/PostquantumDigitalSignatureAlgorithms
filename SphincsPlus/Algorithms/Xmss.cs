using Core.Helpers;
using SphincsPlus.Hashing;

namespace SphincsPlus.Algorithms
{
    internal sealed class Xmss
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly WotsPlus _wotsPlus;
        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public Xmss(SphincsPlusParameters parameters, WotsPlus wotsPlus)
        {
            _parameters = parameters;
            _wotsPlus = wotsPlus;
        }

        public byte[] Node(byte[] skSeed, int i, int z, byte[] pkSeed, Adrs adrs)
        {
            if (z == 0)
            {
                adrs.SetTypeAndClear(SphincsPlusConstants.WotsHash);
                adrs.SetKeyPairAddress(i);

                return _wotsPlus.PkGen(skSeed, pkSeed, adrs);
            }

            byte[] lNode = Node(skSeed, 2 * i, z - 1, pkSeed, adrs);
            byte[] rNode = Node(skSeed, 2 * i + 1, z - 1, pkSeed, adrs);

            adrs.SetTypeAndClear(SphincsPlusConstants.Tree);
            adrs.SetTreeHeight(z);
            adrs.SetTreeIndex(i);

            return _hashing.H(pkSeed, adrs, ByteArrayHelpers.ConcatBytes(lNode, rNode));
        }

        public byte[] Sign(byte[] m, byte[] skSeed, int idx, byte[] pkSeed, Adrs adrs)
        {
            byte[][] auth = new byte[_parameters.HPrime][];
            for (int j = 0; j < _parameters.HPrime; j++)
            {
                int k = (idx / (1 << j)) ^ 1;
                auth[j] = Node(skSeed, k, j, pkSeed, adrs);
            }

            adrs.SetTypeAndClear(SphincsPlusConstants.WotsHash);
            adrs.SetKeyPairAddress(idx);

            byte[] sig = _wotsPlus.Sign(m, skSeed, pkSeed, adrs);
            byte[] sigXmss = ByteArrayHelpers.ConcatBytes(sig, ByteArrayHelpers.ConcatBytes(auth));

            return sigXmss;
        }

        public byte[] PkFromSig(int idx, byte[] sigXmss, byte[] m, byte[] pkSeed, Adrs adrs)
        {
            adrs.SetTypeAndClear(SphincsPlusConstants.WotsHash);
            adrs.SetKeyPairAddress(idx);

            byte[] sig = GetWotsSig(sigXmss);
            byte[][] auth = GetXmssAuth(sigXmss);

            byte[] node0 = _wotsPlus.PkFromSig(sig, m, pkSeed, adrs);

            adrs.SetTypeAndClear(SphincsPlusConstants.Tree);
            adrs.SetTreeIndex(idx);

            for (int k = 0; k < _parameters.HPrime; k++)
            {
                byte[] node1;

                adrs.SetTreeHeight(k + 1);

                if ((idx / (1 << k)) % 2 == 0)
                {
                    adrs.SetTreeIndex(adrs.GetTreeIndex() / 2);
                    node1 = _hashing.H(pkSeed, adrs, ByteArrayHelpers.ConcatBytes(node0, auth[k]));
                }
                else
                {
                    adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) / 2);
                    node1 = _hashing.H(pkSeed, adrs, ByteArrayHelpers.ConcatBytes(auth[k], node0));
                }

                node0 = node1;
            }

            return node0;
        }

        private byte[] GetWotsSig(byte[] sigXmss) => sigXmss[..(_parameters.Len * _parameters.N)];

        private byte[][] GetXmssAuth(byte[] sigXmss)
        {
            byte[][] auth = new byte[_parameters.HPrime][];
            int offset = _parameters.Len * _parameters.N;
            for (int i = 0; i < _parameters.HPrime; i++)
            {
                auth[i] = sigXmss[offset..(offset + _parameters.N)];
                offset += _parameters.N;
            }
            return auth;
        }
    }
}
