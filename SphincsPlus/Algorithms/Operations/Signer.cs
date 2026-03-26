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
        private readonly CommonOperations _commonOperations;

        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public Signer(SphincsPlusParameters parameters)
            : this(parameters, new Fors(parameters), new HyperTree(parameters), new CommonOperations(parameters)) { }

        public Signer(SphincsPlusParameters parameters, Fors fors, HyperTree hyperTree, CommonOperations commonOperations)
        {
            _parameters = parameters;
            _fors = fors;
            _hyperTree = hyperTree;
            _commonOperations = commonOperations;
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
            byte[] optRand = addrnd ?? sk.PkSeed;
            byte[] r = _hashing.PrfMsg(sk.SkPrf, optRand, m);
            byte[] sig = r;
            
            var (idxTree, idxLeaf, md) = _commonOperations.ExtractData(m, sk.PkSeed, sk.PkRoot, r);

            Adrs adrs = _commonOperations.CreateForsTreeAdress(idxTree, idxLeaf);

            byte[] sigFors = _fors.Sign(md, sk.SkSeed, sk.PkSeed, adrs);
            sig = ByteArrayHelpers.ConcatBytes(sig, sigFors);

            byte[] pkFors = _fors.PkFromSig(sigFors, md, sk.PkSeed, adrs);

            byte[] sigHt = _hyperTree.Sign(pkFors, sk.SkSeed, sk.PkSeed, idxTree, idxLeaf);

            sig = ByteArrayHelpers.ConcatBytes(sig, sigHt);

            return sig;
        }
    }
}
