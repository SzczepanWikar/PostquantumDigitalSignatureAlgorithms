using Core.Helpers;
using SphincsPlus.ADRS;
using SphincsPlus.Hashing;
using System;
using System.Collections.Generic;
using System.Text;

namespace SphincsPlus.Algorithms.Operations
{
    internal sealed class CommonOperations
    {
        private readonly SphincsPlusParameters _parameters;

        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public CommonOperations(SphincsPlusParameters parameters)
        {
            _parameters = parameters;
        }

        /// <summary>
        /// Computes the message digest via H_msg(R, PK.seed, PK.root, M) and splits the output
        /// into the FORS message digest md (⌈k·a/8⌉ bytes), tree index idxTree
        /// (⌈(h − h/d)/8⌉ bytes mod 2^(h−h/d)), and leaf index idxLeaf (⌈h/d/8⌉ bytes mod 2^(h/d)).
        /// Used by both slh_sign_internal and slh_verify_internal.
        /// </summary>
        public (ulong idxTree, int idxLeaf, byte[] md) ExtractData(byte[] m, byte[] pkSeed, byte[] pkRoot, byte[] r)
        {
            byte[] digest = _hashing.HMsg(r, pkSeed, pkRoot, m);

            int mdLen = (_parameters.K * _parameters.A + 7) / 8;
            int idxTreeLen = (_parameters.H - _parameters.HPrime + 7) / 8;
            int idxLeafLen = (_parameters.HPrime + 7) / 8;

            byte[] md = digest[..mdLen];
            byte[] tmpIdxTree = digest[mdLen..(mdLen + idxTreeLen)];
            byte[] tmpIdxLeaf = digest[(mdLen + idxTreeLen)..(mdLen + idxTreeLen + idxLeafLen)];

            int exponent = _parameters.H - _parameters.HPrime;
            ulong idxTree = exponent < 64
                ? ByteConversions.ToUint64(tmpIdxTree) % (1UL << exponent)
                : ByteConversions.ToUint64(tmpIdxTree);
            int idxLeaf = ByteConversions.ToInt(tmpIdxLeaf) % (1 << (_parameters.H / _parameters.D));

            return (idxTree, idxLeaf, md);
        }

        /// <summary>
        /// Constructs a FORS_TREE address with the given tree index and key-pair (leaf) address.
        /// Used to derive the shared ADRS context passed to FORS signing and verification.
        /// </summary>
        public Adrs CreateForsTreeAddress(ulong idxTree, int idxLeaf)
        {
            Adrs adrs = new(ByteConversions.ToByte(0, 32));

            adrs.SetTreeAddress(idxTree);
            adrs.SetTypeAndClear(AdrsTypes.ForsTree);
            adrs.SetKeyPairAddress(idxLeaf);

            return adrs;
        }
    }
}
