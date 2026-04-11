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
        /// Algorithm 19 — slh_sign_internal. Computes R = PRF_msg(SK.prf, opt_rand, M)
        /// (opt_rand = addrnd if hedged, PK.seed if deterministic), extracts (idxTree, idxLeaf, md)
        /// from H_msg, produces SIG_FORS via fors_sign and pkFors via fors_pkFromSig, then signs
        /// pkFors through all d hypertree layers via ht_sign. Returns σ = R ‖ SIG_FORS ‖ SIG_HT.
        /// </summary>
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
