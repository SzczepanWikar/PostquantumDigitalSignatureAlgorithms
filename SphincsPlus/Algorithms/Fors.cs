using Core.Helpers;
using SphincsPlus.Hashing;

namespace SphincsPlus.Algorithms
{
    internal sealed class Fors
    {
        private readonly SphincsPlusParameters _parameters;
        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public Fors(SphincsPlusParameters parameters)
        {
            _parameters = parameters;
        }

        /// <summary>
        /// Algorithm 14: fors_skGen — generates a FORS private-key value.
        /// </summary>
        /// <param name="skSeed">Secret seed SK.seed.</param>
        /// <param name="pkSeed">Public seed PK.seed.</param>
        /// <param name="adrs">Address with layer=0, tree address, type=FORS_TREE, key pair address set.</param>
        /// <param name="idx">Index of the secret value within the FORS trees.</param>
        /// <returns>n-byte FORS private-key value.</returns>
        public byte[] SkGen(byte[] skSeed, byte[] pkSeed, Adrs adrs, int idx)
        {
            Adrs skAdrs = new Adrs(adrs);
            skAdrs.SetTypeAndClear(SphincsPlusConstants.ForsPrf);
            skAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());
            skAdrs.SetTreeIndex(idx);

            byte[] signatureKey = _hashing.Prf(pkSeed, skSeed, skAdrs);

            return signatureKey;
        }

        /// <summary>
        /// Algorithm 15: fors_node — computes the root of a Merkle subtree of FORS public values.
        /// </summary>
        /// <param name="skSeed">Secret seed SK.seed.</param>
        /// <param name="i">Target node index.</param>
        /// <param name="z">Target node height within the FORS Merkle tree.</param>
        /// <param name="pkSeed">Public seed PK.seed.</param>
        /// <param name="adrs">Address with layer=0, tree address, type=FORS_TREE, key pair address set.</param>
        /// <returns>n-byte root node.</returns>
        public byte[] Node(byte[] skSeed, int i, int z, byte[] pkSeed, Adrs adrs)
        {
            if (z == 0)
            {
                byte[] sk = SkGen(skSeed, pkSeed, adrs, i);
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex(i);

                return _hashing.F(pkSeed, adrs, sk);
            }

            byte[] lNode = Node(skSeed, 2 * i, z - 1, pkSeed, adrs);
            byte[] rNode = Node(skSeed, 2 * i + 1, z - 1, pkSeed, adrs);
            adrs.SetTreeHeight(z);
            adrs.SetTreeIndex(i);

            return _hashing.H(pkSeed, adrs, ByteArrayHelpers.ConcatBytes(lNode, rNode));
        }

        /// <summary>
        /// Algorithm 16: fors_sign — generates a FORS signature on a message digest.
        /// </summary>
        /// <param name="md">Message digest of ⌈k·a/8⌉ bytes (k·a bits used).</param>
        /// <param name="skSeed">Secret seed SK.seed.</param>
        /// <param name="pkSeed">Public seed PK.seed.</param>
        /// <param name="adrs">Address with layer=0, tree address, type=FORS_TREE, key pair address set.</param>
        /// <returns>FORS signature SIG_FORS of k·(1+a)·n bytes.</returns>
        public byte[] Sign(byte[] md, byte[] skSeed, byte[] pkSeed, Adrs adrs)
        {
            byte[] sigFors = [];
            int[] indices = ByteConversions.Base2b(md, _parameters.A, _parameters.K);

            for (int i = 0; i < _parameters.K; i++)
            {
                byte[] signatureKey = SkGen(
                    skSeed,
                    pkSeed,
                    adrs,
                    i * (1 << _parameters.A) + indices[i]
                );
                sigFors = ByteArrayHelpers.ConcatBytes(sigFors, signatureKey);

                byte[] auth = [];

                for (int j = 0; j < _parameters.A; j++)
                {
                    int s = (indices[i] / (1 << j)) ^ 1;
                    auth = ByteArrayHelpers.ConcatBytes(
                        auth,
                        Node(skSeed, i * (1 << (_parameters.A - j)) + s, j, pkSeed, adrs)
                    );
                }
                sigFors = ByteArrayHelpers.ConcatBytes(sigFors, auth);
            }

            return sigFors;
        }

        /// <summary>
        /// Algorithm 17: fors_pkFromSig — computes a FORS public key from a FORS signature.
        /// </summary>
        /// <param name="sigFors">FORS signature SIG_FORS of k·(1+a)·n bytes.</param>
        /// <param name="md">Message digest of ⌈k·a/8⌉ bytes (k·a bits used).</param>
        /// <param name="pkSeed">Public seed PK.seed.</param>
        /// <param name="adrs">Address with layer=0, tree address, type=FORS_TREE, key pair address set.</param>
        /// <returns>n-byte FORS public key.</returns>
        public byte[] PkFromSig(byte[] sigFors, byte[] md, byte[] pkSeed, Adrs adrs)
        {
            int[] indices = ByteConversions.Base2b(md, _parameters.A, _parameters.K);
            byte[] root = [];

            for (int i = 0; i < _parameters.K; i++)
            {
                byte[] sk = GetSk(sigFors, i);
                
                adrs.SetTreeHeight(0);
                adrs.SetTreeIndex(i * (1 << _parameters.A) + indices[i]);

                byte[] node0 = _hashing.F(pkSeed, adrs, sk);

                byte[][] auth = GetAuth(sigFors, i);

                for (int j = 0; j < _parameters.A; j++)
                {
                    adrs.SetTreeHeight(j + 1);
                    if ((int)(indices[i]/(1 << j)) % 2 == 0)
                    {
                        adrs.SetTreeIndex(adrs.GetTreeIndex() / 2);
                        node0 = _hashing.H(pkSeed, adrs, ByteArrayHelpers.ConcatBytes(node0, auth[j]));
                        continue;
                    }

                    adrs.SetTreeIndex((adrs.GetTreeIndex() - 1) /2);
                    node0 = _hashing.H(pkSeed, adrs, ByteArrayHelpers.ConcatBytes(auth[j], node0));
                }

                root = ByteArrayHelpers.ConcatBytes(root, node0);
            }

            Adrs forsPkAdrs = new Adrs(adrs);
            forsPkAdrs.SetTypeAndClear(SphincsPlusConstants.ForsRoots);
            forsPkAdrs.SetKeyPairAddress(adrs.GetKeyPairAddress());
            byte[] pk = _hashing.T(pkSeed, forsPkAdrs, root);

            return pk;
        }

        private byte[] GetSk(byte[] sigFors, int i)
        {
            int offset = i * (1 + _parameters.A) * _parameters.N;
            return sigFors[offset..(offset + _parameters.N)];
        }

        private byte[][] GetAuth(byte[] sigFors, int i)
        {
            byte[][] auth = new byte[_parameters.A][];
            int offset = i * (1 + _parameters.A) * _parameters.N + _parameters.N;

            for (int j = 0; j < _parameters.A; j++)
            {
                auth[j] = sigFors[offset..(offset + _parameters.N)];
                offset += _parameters.N;
            }

            return auth;
        }
    }
}
