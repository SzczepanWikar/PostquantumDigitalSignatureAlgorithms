using SphincsPlus.Hashing;

namespace SphincsPlus
{
    public sealed class SphincsPlusParameters
    {
        /// <summary>
        /// Security parameter — hash output and private key element size in bytes
        /// </summary>
        public int N { get; }

        /// <summary>
        /// Total height of the hypertree
        /// </summary>
        public int H { get; }

        /// <summary>
        /// Number of layers in the hypertree
        /// </summary>
        public int D { get; }

        /// <summary>
        /// Height of each FORS binary hash tree
        /// </summary>
        public int A { get; }

        /// <summary>
        /// Number of FORS trees
        /// </summary>
        public int K { get; }

        /// <summary>
        /// Message digest size in bytes
        /// </summary>
        public int M { get; }

        /// <summary>
        /// Height of each individual Merkle tree layer in the hypertree (H / D)
        /// </summary>
        public int HPrime { get; }

        /// <summary>
        /// Winternitz parameter — fixed at 16 for all FIPS 205 parameter sets
        /// </summary>
        public int W { get; } = 16;

        /// <summary>
        /// log₂(W) — bits per WOTS+ chain step, fixed at 4
        /// </summary>
        public int LogW { get; } = 4;

        /// <summary>
        /// Total number of n-byte values in a WOTS+ signature — Len1 + Len2
        /// </summary>
        public int Len { get; }

        /// <summary>
        /// Public key size in bytes (2n)
        /// </summary>
        public int PublicKeySize { get; }

        /// <summary>
        /// Secret key size in bytes (4n)
        /// </summary>
        public int SecretKeySize { get; }

        /// <summary>
        /// Signature size in bytes — (1 + k·(a+1) + h + d·len) · n
        /// </summary>
        public int SignatureSize { get; }

        /// <summary>
        /// Set of hashing functions
        /// </summary>
        internal ISphincsPlusHashing Hashing { get; }

        internal SphincsPlusParameters(int n, int h, int d, int a, int k, int m, ISphincsPlusHashing sphincsPlusHashing)
        {
            N = n;
            H = h;
            D = d;
            A = a;
            K = k;
            M = m;
            Hashing = sphincsPlusHashing;

            HPrime = H / D;
            Len = 2 * N + 3;
            PublicKeySize = 2 * N;
            SecretKeySize = 4 * N;
            SignatureSize = (1 + K * (A + 1) + H + D * Len) * N;
        }
    }
}
