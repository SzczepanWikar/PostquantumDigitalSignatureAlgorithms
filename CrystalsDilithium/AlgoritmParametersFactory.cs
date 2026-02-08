namespace CrystalsDilithium
{
    public static class DilithiumParametersProvider
    {
        private static int Gamma2(byte mode) => mode switch
        {
            2 => (DilithiumParameters.Q - 1) / 88,
            3 => (DilithiumParameters.Q - 1) / 32,
            5 => (DilithiumParameters.Q - 1) / 32,
            _ => throw new ArgumentOutOfRangeException(nameof(mode), "Invalid mode. Supported modes are 2, 3, and 5.")
        };

        public static DilithiumParameters SecurityLevel2Parameters => new(
            d: 13,
            tau: 39,
            gamma1: 1 << 17,
            gamma2: Gamma2(2),
            aMatrixDimensions: (k: 4, l: 4),
            eta: 2,
            omega: 80
        );

        public static DilithiumParameters SecurityLevel3Parameters => new(
            d: 13,
            tau: 49,
            gamma1: 1 << 19,
            gamma2: Gamma2(3),
            aMatrixDimensions: (k: 6, l: 5),
            eta: 4,
            omega: 55
        );

        public static DilithiumParameters SecurityLevel5Parameters => new(
            d: 13,
            tau: 60,
            gamma1: 1 << 19,
            gamma2: Gamma2(5),
            aMatrixDimensions: (k: 8, l: 7),
            eta: 4,
            omega: 75
        );
    }
}
