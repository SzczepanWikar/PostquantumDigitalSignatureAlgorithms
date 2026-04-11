using SphincsPlus.Models;

namespace SphincsPlus.Algorithms.Operations
{
    internal sealed class KeyGenerator
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly Xmss _xmss;

        public KeyGenerator(SphincsPlusParameters parameters)
            : this(parameters, new Xmss(parameters)) { }

        public KeyGenerator(SphincsPlusParameters parameters, Xmss xmss)
        {
            _parameters = parameters;
            _xmss = xmss;
        }

        /// <summary>
        /// Algorithm 18 — slh_keygen_internal. Computes PK.root as the XMSS root of the
        /// top-layer tree (layer d−1, node 0, height h') and assembles the key pair:
        /// SK = (SK.seed, SK.prf, PK.seed, PK.root) and PK = (PK.seed, PK.root).
        /// </summary>
        internal (SecretKey sk, PublicKey pk) KeyGenInternal(byte[] skSeed, byte[] skPrf, byte[] pkSeed)
        {
            Adrs adrs = new(ByteConversions.ToByte(0, 32));
            adrs.SetLayerAddress(_parameters.D - 1);
            byte[] pkRoot = _xmss.Node(skSeed, 0, _parameters.HPrime, pkSeed, adrs);

            SecretKey sk = new(skSeed, skPrf, pkSeed, pkRoot);
            PublicKey pk = new(pkSeed, pkRoot);

            return (sk, pk);
        }
    }
}
