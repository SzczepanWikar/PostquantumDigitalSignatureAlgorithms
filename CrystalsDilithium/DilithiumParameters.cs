namespace CrystalsDilithium
{
    public sealed class DilithiumParameters
    {
        /// <summary>
        /// Modulus
        /// </summary>
        public const int Q = 8380417;
        /// <summary>
        /// Dropped bits from t
        /// </summary>
        public byte D { get; }
        public int Tau { get; }
        /// <summary>
        /// collision strength of c wave
        /// </summary>
        public int Lambda { get; }
        /// <summary>
        /// y coefficient range
        /// </summary>
        public int Gamma1 { get; }
        /// <summary>
        /// Low-order rounding range
        /// </summary>
        public int Gamma2 { get; }
        /// <summary>
        /// Dimensions of matrix A (k x l)
        /// </summary>
        public (byte K, byte L) AMatrixDimensions { get; }
        /// <summary>
        /// Secret key range
        /// </summary>
        public byte Eta { get; }
        public byte Omega { get; }
        public int Beta { get; }

        public DilithiumParameters(
            byte d,
            int tau,
            int gamma1,
            int gamma2,
            int lambda,
            (byte k, byte l) aMatrixDimensions,
            byte eta,
            byte omega
        )
        {
            D = d;
            Tau = tau;
            Gamma1 = gamma1;
            Gamma2 = gamma2;
            Lambda = lambda;
            AMatrixDimensions = aMatrixDimensions;
            Eta = eta;
            Omega = omega;

            Beta = Tau * Eta;
        }
    }
}
