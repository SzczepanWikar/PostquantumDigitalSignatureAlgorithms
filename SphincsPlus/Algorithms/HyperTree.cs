using Core.Helpers;
using SphincsPlus.ADRS;

namespace SphincsPlus.Algorithms
{
    internal sealed class HyperTree
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly Xmss _xmss;

        public HyperTree(SphincsPlusParameters parameters)
            : this(parameters, new Xmss(parameters)) { }

        public HyperTree(SphincsPlusParameters parameters, Xmss xmss)
        {
            _parameters = parameters;
            _xmss = xmss;
        }

        /// <summary>
        /// Algorithm 12 — ht_sign. Produces a hypertree signature SIG_HT of
        /// d·(h' + len)·n bytes on message <paramref name="m"/>. Signs m with the XMSS tree
        /// at layer 0 and tree index <paramref name="idxTree"/>, then uses the resulting XMSS root
        /// as the message for each subsequent layer, advancing idxTree rightward by h' bits per layer.
        /// </summary>
        public byte[] Sign(byte[] m, byte[] skSeed, byte[] pkSeed, ulong idxTree, int idxLeaf)
        {
            Adrs adrs = new(ByteConversions.ToByte(0, 32));
            adrs.SetTreeAddress(idxTree);

            byte[] sigTmp = _xmss.Sign(m, skSeed, idxLeaf, pkSeed, adrs);
            byte[] sigHt = sigTmp.ToArray();
            byte[] root = _xmss.PkFromSig(idxLeaf, sigTmp, m, pkSeed, adrs);

            for (int j = 1; j < _parameters.D; j++)
            {
                idxLeaf = (int)(idxTree % (ulong)(1 << _parameters.HPrime));
                idxTree = idxTree >> _parameters.HPrime;

                adrs.SetLayerAddress(j);
                adrs.SetTreeAddress(idxTree);

                sigTmp = _xmss.Sign(root, skSeed, idxLeaf, pkSeed, adrs);
                sigHt = ByteArrayHelpers.ConcatBytes(sigHt, sigTmp);

                if (j < _parameters.D - 1)
                {
                    root = _xmss.PkFromSig(idxLeaf, sigTmp, root, pkSeed, adrs);
                }
            }

            return sigHt;
        }

        /// <summary>
        /// Algorithm 13 — ht_verify. Verifies hypertree signature <paramref name="sigHt"/> on
        /// message <paramref name="m"/>. Recovers the XMSS root at layer 0 via
        /// <see cref="Xmss.PkFromSig"/>, then propagates the root upward through d layers,
        /// advancing idxTree rightward by h' bits per layer. Returns <see langword="true"/> iff
        /// the final recovered root equals <paramref name="pkRoot"/>.
        /// </summary>
        public bool Verify(
            byte[] m,
            byte[] sigHt,
            byte[] pkSeed,
            ulong idxTree,
            int idxLeaf,
            byte[] pkRoot
        )
        {
            Adrs adrs = new(ByteConversions.ToByte(0, 32));
            adrs.SetTreeAddress(idxTree);

            byte[] sigTmp = GetXmssSignature(sigHt, 0);
            byte[] node = _xmss.PkFromSig(idxLeaf, sigTmp, m, pkSeed, adrs);

            for (int j = 1; j < _parameters.D; j++)
            {
                idxLeaf = (int)(idxTree % (ulong)(1 << _parameters.HPrime));
                idxTree = idxTree >> _parameters.HPrime;

                adrs.SetLayerAddress(j);
                adrs.SetTreeAddress(idxTree);

                sigTmp = GetXmssSignature(sigHt, j);
                node = _xmss.PkFromSig(idxLeaf, sigTmp, node, pkSeed, adrs);
            }

            return node.SequenceEqual(pkRoot);
        }

        /// <summary>
        /// Extracts the j-th XMSS signature from the flat SIG_HT byte array.
        /// Each XMSS signature occupies (len + h')·n bytes.
        /// </summary>
        private byte[] GetXmssSignature(byte[] sig, int j) =>
            sig[
                (j * ((_parameters.Len + _parameters.HPrime) * _parameters.N))..(
                    (j + 1) * ((_parameters.Len + _parameters.HPrime) * _parameters.N)
                )
            ];
    }
}
