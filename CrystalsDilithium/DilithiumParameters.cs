namespace CrystalsDilithium
{
    public sealed class DilithiumParameters
    {
        /// <summary>
        /// Modulus
        /// </summary>
        public uint Q { get; }
        /// <summary>
        /// Dropped bits from t
        /// </summary>
        public byte D { get; }
        public uint Tau { get; }
        /// <summary>
        /// y coefficient range
        /// </summary>
        public uint Gamma1 { get; }
        /// <summary>
        /// Low-order rounding range
        /// </summary>
        public uint Gamma2 { get; }
        /// <summary>
        /// Dimensions of matrix A (k x l)
        /// </summary>
        public (byte K, byte L) AMatrixDimensions { get; }
        /// <summary>
        /// Secret key range
        /// </summary>
        public byte Eta { get; }
        public byte Omega { get; }
        public uint Beta { get; }

        public DilithiumParameters(
            uint q,
            byte d,
            uint tau,
            uint gamma1,
            uint gamma2,
            (byte k, byte l) aMatrixDimensions,
            byte eta,
            byte omega
        )
        {
            Q = q;
            D = d;
            Tau = tau;
            Gamma1 = gamma1;
            Gamma2 = gamma2;
            AMatrixDimensions = aMatrixDimensions;
            Eta = eta;
            Omega = omega;

            Beta = Tau * Eta;
        }
    }
}
