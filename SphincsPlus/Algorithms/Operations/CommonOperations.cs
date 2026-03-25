using Core.Helpers;
using SphincsPlus.Hashing;
using SphincsPlus.Models;
using System;
using System.Collections.Generic;
using System.Text;

namespace SphincsPlus.Algorithms.Operations
{
    internal sealed class CommonOperations
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly Fors _fors;
        private readonly HyperTree _hyperTree;

        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public CommonOperations(SphincsPlusParameters parameters, Fors fors, HyperTree hyperTree)
        {
            _parameters = parameters;
            _fors = fors;
            _hyperTree = hyperTree;
        }

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

        public Adrs CreateForsTreeAdress(ulong idxTree, int idxLeaf)
        {
            Adrs adrs = new(ByteConversions.ToByte(0, 32));

            adrs.SetTreeAddress(idxTree);
            adrs.SetTypeAndClear(SphincsPlusConstants.ForsTree);
            adrs.SetKeyPairAddress(idxLeaf);

            return adrs;
        }
    }
}
