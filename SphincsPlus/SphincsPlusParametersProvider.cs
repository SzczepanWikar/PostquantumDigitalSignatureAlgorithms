using SphincsPlus.Hashing;

namespace SphincsPlus
{
    public static class SphincsPlusParametersProvider
    {
        public static SphincsPlusParameters Sha2_128s =>
            new(
                n: 16,
                h: 63,
                d: 7,
                a: 12,
                k: 14,
                m: 30,
                sphincsPlusHashing: ShaLevelOne(n: 16, m: 30)
            );

        public static SphincsPlusParameters Sha2_128f =>
            new(
                n: 16,
                h: 66,
                d: 22,
                a: 6,
                k: 33,
                m: 34,
                sphincsPlusHashing: ShaLevelOne(n: 16, m: 34)
            );

        public static SphincsPlusParameters Shake_128s =>
            new(n: 16, h: 63, d: 7, a: 12, k: 14, m: 30, sphincsPlusHashing: Shake(n: 16, m: 30));

        public static SphincsPlusParameters Shake_128f =>
            new(n: 16, h: 66, d: 22, a: 6, k: 33, m: 34, sphincsPlusHashing: Shake(n: 16, m: 34));

        public static SphincsPlusParameters Sha2_192s =>
            new(n: 24, h: 63, d: 7, a: 14, k: 17, m: 39, sphincsPlusHashing: Sha(n: 24, m: 39));

        public static SphincsPlusParameters Sha2_192f =>
            new(n: 24, h: 66, d: 22, a: 8, k: 33, m: 42, sphincsPlusHashing: Sha(n: 24, m: 42));

        public static SphincsPlusParameters Shake_192s =>
            new(n: 24, h: 63, d: 7, a: 14, k: 17, m: 39, sphincsPlusHashing: Shake(n: 24, m: 39));

        public static SphincsPlusParameters Shake_192f =>
            new(n: 24, h: 66, d: 22, a: 8, k: 33, m: 42, sphincsPlusHashing: Shake(n: 24, m: 42));

        public static SphincsPlusParameters Sha2_256s =>
            new(n: 32, h: 64, d: 8, a: 14, k: 22, m: 47, sphincsPlusHashing: Sha(n: 32, m: 47));

        public static SphincsPlusParameters Sha2_256f =>
            new(n: 32, h: 68, d: 17, a: 9, k: 35, m: 49, sphincsPlusHashing: Sha(n: 32, m: 49));

        public static SphincsPlusParameters Shake_256s =>
            new(n: 32, h: 64, d: 8, a: 14, k: 22, m: 47, sphincsPlusHashing: Shake(n: 32, m: 47));

        public static SphincsPlusParameters Shake_256f =>
            new(n: 32, h: 68, d: 17, a: 9, k: 35, m: 49, sphincsPlusHashing: Shake(n: 32, m: 49));

        private static ISphincsPlusHashing ShaLevelOne(int n, int m) => new ShaLevelOneFacade(n, m);

        private static ISphincsPlusHashing Sha(int n, int m) => new ShaFacade(n, m);

        private static ISphincsPlusHashing Shake(int n, int m) => new ShakeFacade(n, m);
    }
}
