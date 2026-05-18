using Core.Helpers;
using SphincsPlus.Algorithms;

namespace SphincsPlus.ADRS
{
    /// <summary>
    /// ADRS — 32-byte address structure that domain-separates every tweakable hash call in
    /// SLH-DSA. Encodes the position in the hypertree (layer address, tree address, type)
    /// together with type-specific fields: key-pair address, chain/tree-height, and
    /// hash/tree-index. (FIPS 205 §4.2)
    /// </summary>
    internal sealed class Adrs
    {
        private byte[] _content = new byte[32];

        public IReadOnlyCollection<byte> Content { get => _content; }

        public Adrs()
        {}

        public Adrs(byte[] content)
        {
            if(content.Length != 32)
            {
                throw new ArgumentException("_content length must be 32.");
            }

            _content = content.ToArray();
        }

        public Adrs(Adrs adrs)
        {
            _content = adrs.Content.ToArray();
        }

        /// <summary>
        /// §4.3 — setLayerAddress (no algorithm number). Sets the 4-byte layer address field
        /// (bytes [0..3]) to <paramref name="l"/>. Identifies the XMSS tree layer within the
        /// hypertree (0 = bottom, d−1 = top).
        /// </summary>
        public void SetLayerAddress(int l)
        {
            byte[] layer = ByteConversions.ToByte(l, 4);

            byte[] postfix = _content.Skip(4).ToArray();

            _content = ByteArrayHelpers.ConcatBytes(layer, postfix);
        }

        /// <summary>
        /// §4.3 — setTreeAddress (no algorithm number). Sets the 12-byte tree address field
        /// (bytes [4..15]) to <paramref name="t"/>. Identifies the specific XMSS tree within
        /// the given layer of the hypertree.
        /// </summary>
        public void SetTreeAddress(ulong t)
        {
            byte[] layer = _content.Take(4).ToArray();
            byte[] tree = ByteConversions.ToByte(t, 12);
            byte[] postfix = _content.Skip(16).ToArray();

            _content = ByteArrayHelpers.ConcatBytes(layer, tree, postfix);
        }

        /// <summary>
        /// §4.3 — setTypeAndClear (no algorithm number). Sets the 4-byte type field
        /// (bytes [16..19]) to <paramref name="y"/> and zeroes the 12 type-specific bytes
        /// [20..31]. Must be called before setting any type-specific fields to avoid stale data
        /// from a previous address type.
        /// </summary>
        public void SetTypeAndClear(AdrsTypes y) => SetTypeAndClear((int)y);

        /// <summary>
        /// §4.3 — setTypeAndClear (no algorithm number). Sets the 4-byte type field
        /// (bytes [16..19]) to <paramref name="y"/> and zeroes the 12 type-specific bytes
        /// [20..31]. Must be called before setting any type-specific fields to avoid stale data
        /// from a previous address type.
        /// </summary>
        public void SetTypeAndClear(int y)
        {
            byte[] prefix = _content.Take(16).ToArray();
            byte[] type = ByteConversions.ToByte(y, 4);
            byte[] postfix = new byte[12];

            _content = ByteArrayHelpers.ConcatBytes(prefix, type, postfix);
        }

        /// <summary>
        /// §4.3 — setKeyPairAddress (no algorithm number). Sets the 4-byte key-pair address
        /// field (bytes [20..23]) to <paramref name="i"/>. Selects the WOTS+ key pair within
        /// an XMSS tree or the FORS instance within the virtual structure. Used by WOTS_HASH,
        /// WOTS_PRF, WOTS_PK, FORS_TREE, FORS_ROOTS, and FORS_PRF address types.
        /// </summary>
        public void SetKeyPairAddress(int i)
        {
            byte[] prefix = _content.Take(20).ToArray();
            byte[] keyPair = ByteConversions.ToByte(i, 4);
            byte[] postfix = _content.Skip(24).ToArray();

            _content = ByteArrayHelpers.ConcatBytes(prefix, keyPair, postfix);
        }

        /// <summary>
        /// §4.3 — setChainAddress (no algorithm number). Sets the 4-byte chain address field
        /// (bytes [24..27]) to <paramref name="i"/>. Identifies the chain index within a WOTS+
        /// key pair (0 to len−1). Used by WOTS_HASH and WOTS_PRF address types.
        /// </summary>
        public void SetChainAddress(int i)
        {
            byte[] prefix = _content.Take(24).ToArray();
            byte[] chain = ByteConversions.ToByte(i, 4);
            byte[] postfix = _content.Skip(28).ToArray();

            _content = ByteArrayHelpers.ConcatBytes(prefix, chain, postfix);
        }

        /// <summary>
        /// §4.3 — setTreeHeight (no algorithm number). Sets the 4-byte tree-height field
        /// (bytes [24..27]) to <paramref name="i"/>. Identifies the level within a FORS or XMSS
        /// Merkle tree (0 = leaf level). Shares the same byte range as the chain address; used
        /// by FORS_TREE and TREE address types.
        /// </summary>
        public void SetTreeHeight(int i) => SetChainAddress(i);

        /// <summary>
        /// §4.3 — setHashAddress (no algorithm number). Sets the 4-byte hash address field
        /// (bytes [28..31]) to <paramref name="i"/>. Identifies the step index within a WOTS+
        /// chain (0 to w−1). Used by WOTS_HASH and WOTS_PRF address types.
        /// </summary>
        public void SetHashAddress(int i)
        {
            byte[] prefix = _content.Take(28).ToArray();
            byte[] hash = ByteConversions.ToByte(i, 4);

            _content = ByteArrayHelpers.ConcatBytes(prefix, hash);
        }

        /// <summary>
        /// §4.3 — setTreeIndex (no algorithm number). Sets the 4-byte tree-index field
        /// (bytes [28..31]) to <paramref name="i"/>. Identifies the node position within a
        /// level of a FORS or XMSS Merkle tree. Shares the same byte range as the hash address;
        /// used by FORS_TREE and TREE address types.
        /// </summary>
        public void SetTreeIndex(int i) => SetHashAddress(i);

        /// <summary>
        /// §4.3 — getKeyPairAddress (no algorithm number). Returns the 4-byte key-pair address
        /// encoded in bytes [20..23].
        /// </summary>
        public int GetKeyPairAddress() => ByteConversions.ToInt(_content[20..24]);

        /// <summary>
        /// §4.3 — getTreeIndex (no algorithm number). Returns the 4-byte tree-index encoded in
        /// bytes [28..31].
        /// </summary>
        public int GetTreeIndex() => ByteConversions.ToInt(_content[28..32]);

        /// <summary>
        /// §4.3 — compress (no algorithm number). Returns the 22-byte compressed address
        /// (ADRS^c) used by SHA2-based instantiations. Extracts: the last byte of the layer
        /// address [3..4], the last 8 bytes of the tree address [8..16], the last byte of the
        /// type field [19..20], and all 12 type-specific bytes [20..32].
        /// </summary>
        public byte[] Compress() =>
            ByteArrayHelpers.ConcatBytes(_content[3..4], _content[8..16], _content[19..20], _content[20..32]);
    }
}
