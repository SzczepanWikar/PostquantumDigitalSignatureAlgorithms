using SphincsPlus.Hashing;
using SphincsPlus.Models;

namespace SphincsPlus.Algorithms.Operations
{
    internal sealed class Verifier
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly Fors _fors;
        private readonly HyperTree _hyperTree;
        private readonly CommonOperations _commonOperations;

        private ISphincsPlusHashing _hashing => _parameters.Hashing;

        public Verifier(SphincsPlusParameters parameters)
            : this(parameters, new Fors(parameters), new HyperTree(parameters), new CommonOperations(parameters)) { }

        public Verifier(SphincsPlusParameters parameters, Fors fors, HyperTree hyperTree, CommonOperations commonOperations)
        {
            _parameters = parameters;
            _fors = fors;
            _hyperTree = hyperTree;
            _commonOperations = commonOperations;
        }

        /// <summary>
        /// Algorithm 20 — slh_verify_internal.
        /// </summary>
        /// <param name="m">Message that was signed.</param>
        /// <param name="sig">SLH-DSA signature: R ‖ SIG_FORS ‖ SIG_HT.</param>
        /// <param name="pk">Public key (PK.seed, PK.root).</param>
        /// <returns><c>true</c> if the signature is valid; <c>false</c> otherwise.</returns>
        /// <summary>
        /// Algorithm 20 — slh_verify_internal. Verifies signature <paramref name="sig"/> on
        /// message <paramref name="m"/> against public key <paramref name="pk"/>. Rejects
        /// immediately if the signature length is incorrect. Extracts R, SIG_FORS and SIG_HT,
        /// derives (idxTree, idxLeaf, md) from H_msg, recovers pkFors via fors_pkFromSig, then
        /// returns <see langword="true"/> iff ht_verify accepts pkFors against PK.root.
        /// </summary>
        internal bool VerifyInternal(byte[] m, byte[] sig, PublicKey pk)
        {
            int correctSigLength = (1 + _parameters.K * (1 + _parameters.A) + _parameters.H + _parameters.D * _parameters.Len) * _parameters.N;

            if (sig.Length != correctSigLength)
            {
                return false;
            }
            byte[] r = GetR(sig);
            byte[] sigFors = GetSigFors(sig);
            byte[] sigHt = GetSigHt(sig);

            var (idxTree, idxLeaf, md) = _commonOperations.ExtractData(m, pk.PkSeed, pk.PkRoot, r);

            Adrs adrs = _commonOperations.CreateForsTreeAdress(idxTree, idxLeaf);

            byte[] pkFors = _fors.PkFromSig(sigFors, md, pk.PkSeed, adrs);

            bool verificationResult = _hyperTree.Verify(pkFors, sigHt, pk.PkSeed, idxTree, idxLeaf, pk.PkRoot);

            return verificationResult;
        }
        /// <summary>
        /// Extracts R (n bytes) from the beginning of the flat signature byte array σ = R ‖ SIG_FORS ‖ SIG_HT.
        /// </summary>
        private byte[] GetR(byte[] sig) => sig[.._parameters.N];
        /// <summary>
        /// Extracts SIG_FORS of k·(1 + a)·n bytes from the flat signature byte array,
        /// starting after the n-byte R value.
        /// </summary>
        private byte[] GetSigFors(byte[] sig)
        {
            int start = _parameters.N;
            int end = (1 + _parameters.K * (1 + _parameters.A)) * _parameters.N;
            return sig[start..end];
        }

        /// <summary>
        /// Extracts SIG_HT of d·(h' + len)·n bytes from the flat signature byte array,
        /// starting after R ‖ SIG_FORS.
        /// </summary>
        private byte[] GetSigHt(byte[] sig)
        {
            int start = (1 + _parameters.K * (1 + _parameters.A)) * _parameters.N;
            return sig[start..];
        }
    }
}
