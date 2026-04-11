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
        /// Algorithm 14 — fors_skGen. Generates the FORS secret-key value at index
        /// <paramref name="idx"/> by applying PRF to a FORS_PRF address derived from
        /// <paramref name="adrs"/>. Returns an n-byte secret value.
        /// </summary>
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
        /// Algorithm 15 — fors_node. Recursively computes the n-byte root of the Merkle subtree
        /// of height <paramref name="z"/> rooted at node index <paramref name="i"/>. At height 0
        /// hashes the secret-key value via F; at height z > 0 hashes the two child roots via H.
        /// </summary>
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
        /// Algorithm 16 — fors_sign. Produces a FORS signature SIG_FORS of k·(1+a)·n bytes
        /// on message digest <paramref name="md"/>. Splits md into k indices via base_2b, then
        /// for each tree i concatenates the secret-key value at the chosen leaf with the a-node
        /// authentication path produced by <see cref="Node"/>.
        /// </summary>
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
        /// Algorithm 17 — fors_pkFromSig. Recomputes the n-byte FORS public key from signature
        /// <paramref name="sigFors"/> and message digest <paramref name="md"/>. For each of the k
        /// trees: hashes the secret-key leaf via F, then walks up the a authentication-path nodes
        /// via H. Combines the k tree roots with T_k into the final public key.
        /// </summary>
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

        /// <summary>
        /// Extracts the n-byte secret-key value for tree <paramref name="i"/> from the flat
        /// SIG_FORS byte array. Each tree occupies (1 + a)·n bytes; the sk is the first n bytes.
        /// </summary>
        private byte[] GetSk(byte[] sigFors, int i)
        {
            int offset = i * (1 + _parameters.A) * _parameters.N;
            return sigFors[offset..(offset + _parameters.N)];
        }

        /// <summary>
        /// Extracts the a authentication-path nodes for tree <paramref name="i"/> from the flat
        /// SIG_FORS byte array. Each node is n bytes; they follow the secret-key value in the
        /// (1 + a)·n block for tree i.
        /// </summary>
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
