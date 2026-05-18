using SphincsPlus.ADRS;

namespace SphincsPlus.Hashing
{
    internal interface ISphincsPlusHashing
    {
        /// <summary>
        /// §4.1 — PRF (no algorithm number). Pseudorandom function used to generate secret-key
        /// values for WOTS+ and FORS private keys. Takes <paramref name="pkSeed"/>,
        /// <paramref name="skSeed"/>, and address <paramref name="adrs"/> as input; returns an
        /// n-byte pseudorandom output.
        /// </summary>
        byte[] Prf(byte[] pkSeed, byte[] skSeed, Adrs adrs);

        /// <summary>
        /// §4.1 — PRF_msg (no algorithm number). Pseudorandom function used during signing to
        /// generate the randomizer R. Takes <paramref name="skPrf"/>, optional randomness
        /// <paramref name="optRand"/>, and message <paramref name="m"/> as input; returns an
        /// n-byte randomizer.
        /// </summary>
        byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] m);

        /// <summary>
        /// §4.1 — H (no algorithm number). Tweakable hash function that compresses a 2n-byte
        /// input to n bytes. Used in XMSS and FORS Merkle trees to compute an internal node from
        /// two n-byte children. Takes <paramref name="pkSeed"/>, address <paramref name="adrs"/>,
        /// and 2n-byte input <paramref name="m2"/>.
        /// </summary>
        byte[] H(byte[] pkSeed, Adrs adrs, byte[] m2);

        /// <summary>
        /// §4.1 — H_msg (no algorithm number). Hash function that produces the m-byte message
        /// digest used during signing and verification. The digest is split into the FORS message,
        /// tree index, and leaf index. Takes randomizer <paramref name="r"/>,
        /// <paramref name="pkSeed"/>, root <paramref name="pkRoot"/>, and message
        /// <paramref name="m"/> as input.
        /// </summary>
        byte[] HMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] m);

        /// <summary>
        /// §4.1 — T_ℓ (no algorithm number). Tweakable hash function that compresses an ℓ·n-byte
        /// input to n bytes. Used to compute WOTS+ public keys (ℓ = len) and FORS public keys
        /// (ℓ = k) from a concatenation of chain ends or tree roots. Takes
        /// <paramref name="pkSeed"/>, address <paramref name="adrs"/>, and ℓ·n-byte input
        /// <paramref name="ml"/>.
        /// </summary>
        byte[] T(byte[] pkSeed, Adrs adrs, byte[] ml);

        /// <summary>
        /// §4.1 — F (no algorithm number). Tweakable hash function that maps an n-byte input to
        /// n bytes. Used at each step of a WOTS+ chain and at FORS leaf nodes. Takes
        /// <paramref name="pkSeed"/>, address <paramref name="adrs"/>, and n-byte input
        /// <paramref name="m1"/>.
        /// </summary>
        byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1);
    }
}
