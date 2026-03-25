using Core.Helpers;
using SphincsPlus.Models;

namespace SphincsPlus.Algorithms.Operations
{
    internal sealed class KeyGenerator
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly Xmss _xmss;

        public KeyGenerator(SphincsPlusParameters parameters, Xmss xmss)
        {
            _parameters = parameters;
            _xmss = xmss;
        }

        /// <summary>
        /// Algorithm 18 — slh_keygen_internal.
        /// Computes PK.root as the root of the top-layer XMSS tree and assembles the key pair.
        /// </summary>
        /// <param name="skSeed">Secret seed SK.seed (n bytes)</param>
        /// <param name="skPrf">PRF key SK.prf (n bytes)</param>
        /// <param name="pkSeed">Public seed PK.seed (n bytes)</param>
        /// <returns>
        /// SK = SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root (4n bytes),
        /// PK = PK.seed ‖ PK.root (2n bytes)
        /// </returns>
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
