namespace SphincsPlus.Hashing
{
    internal interface ISphincsPlusHashing
    {
        /// <summary>PRF used to generate secret values in WOTS+ and FORS private keys. (FIPS 205 §4.1)</summary>
        byte[] Prf(byte[] pkSeed, byte[] skSeed, Adrs adrs);

        /// <summary>PRF used to generate the randomizer R for message hashing. (FIPS 205 §4.1)</summary>
        byte[] PrfMsg(byte[] skPrf, byte[] optRand, byte[] m);

        /// <summary>Tweakable hash function: maps a 2n-byte input to n bytes. (FIPS 205 §4.1)</summary>
        byte[] H(byte[] pkSeed, Adrs adrs, byte[] m2);

        /// <summary>Hash function used to generate the message digest. (FIPS 205 §4.1)</summary>
        byte[] HMsg(byte[] r, byte[] pkSeed, byte[] pkRoot, byte[] m);

        /// <summary>Tweakable hash function: maps an ℓn-byte input to n bytes. (FIPS 205 §4.1)</summary>
        byte[] T(byte[] pkSeed, Adrs adrs, byte[] ml);

        /// <summary>Tweakable hash function: maps an n-byte input to n bytes. (FIPS 205 §4.1)</summary>
        byte[] F(byte[] pkSeed, Adrs adrs, byte[] m1);
    }
}
