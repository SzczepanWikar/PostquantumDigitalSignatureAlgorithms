using Core.Helpers;
using SphincsPlus.Hashing;
using SphincsPlus.Models;

namespace SphincsPlus.Algorithms.Operations
{
    internal sealed class Signer
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly Fors _fors;
        private readonly HyperTree _hyperTree;

        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public Signer(SphincsPlusParameters parameters, Fors fors, HyperTree hyperTree)
        {
            _parameters = parameters;
            _fors = fors;
            _hyperTree = hyperTree;
        }

        /// <summary>
        /// Algorithm 19 — slh_sign_internal.
        /// </summary>
        /// <param name="m">Message to sign.</param>
        /// <param name="sk">Encoded private key: SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root (4n bytes).</param>
        /// <param name="addrnd">
        /// Additional randomness for the hedged variant (n bytes).
        /// Pass null for the deterministic variant — opt_rand is set to PK.seed.
        /// </param>
        /// <returns>SLH-DSA signature: R ‖ SIG_FORS ‖ SIG_HT.</returns>
        internal byte[] SignInternal(byte[] m, SecretKey sk, byte[]? addrnd)
        {
            Adrs adrs = new(ByteConversions.ToByte(0, 32));

            byte[] optRand = addrnd ?? sk.PkSeed;
            byte[] r = _hashing.PrfMsg(sk.SkPrf, optRand, m);
            byte[] sig = r;

            
            var (idxTree, idxLeaf, md) = ExtractData(m, sk, r);

            adrs.SetTreeAddress(idxTree);
            adrs.SetTypeAndClear(SphincsPlusConstants.ForsTree);
            adrs.SetKeyPairAddress(idxLeaf);

            byte[] sigFors = _fors.Sign(md, sk.SkSeed, sk.PkSeed, adrs);
            sig = ByteArrayHelpers.ConcatBytes(sig, sigFors);

            byte[] pkFors = _fors.PkFromSig(sigFors, md, sk.PkSeed, adrs);

            byte[] sigHt = _hyperTree.Sign(pkFors, sk.SkSeed, sk.PkSeed, idxTree, idxLeaf);

            sig = ByteArrayHelpers.ConcatBytes(sig, sigHt);

            return sig;
        }

        private (ulong idxTree, int idxLeaf, byte[] md) ExtractData(byte[] m, SecretKey sk, byte[] r)
        {
            byte[] digest = _hashing.HMsg(r, sk.PkSeed, sk.PkRoot, m);

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
    }
}
