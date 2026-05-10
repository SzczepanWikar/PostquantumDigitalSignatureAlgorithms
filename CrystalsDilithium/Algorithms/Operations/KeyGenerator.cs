using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Dto;

namespace CrystalsDilithium.Algorithms.Operations
{
    internal sealed class KeyGenerator
    {
        private readonly DilithiumParameters _parameters;
        private readonly BitAlgorithms _bitAlgorithms;
        private readonly PseudoRandomSampling _pseudoRandomSampler;
        private readonly NttArithmetic _nttArithmetic;
        private readonly Encoding _encoder;
        private readonly DilithiumFunctions _dilithiumFunctions;

        public KeyGenerator(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _bitAlgorithms = new(parameters);
            _pseudoRandomSampler = new(parameters);
            _nttArithmetic = new(parameters);
            _encoder = new(parameters);
            _dilithiumFunctions = new(parameters);
        }

        /// <summary>
        /// Algorithm 6 — ML-DSA.KeyGen_internal. Derives the key pair from the 32-byte seed
        /// <paramref name="ksi"/>: expands ξ into (ρ, ρ', K), samples Â via
        /// <see cref="PseudoRandomSampling.ExpandA"/>, samples (s1, s2) via
        /// <see cref="PseudoRandomSampling.ExpandS"/>, computes t = NTT⁻¹(Â·NTT(s1)) + s2,
        /// splits t into (t1, t0) with Power2Round, then encodes and returns (pk, sk).
        /// </summary>
        internal (byte[] pk, byte[] sk) KeyGenInternal(byte[] ksi)
        {
            (byte[] rho, byte[] rhoPrim, byte[] k) = ExtraxtDataFromSeed(ksi);

            int[][][] aDash = _pseudoRandomSampler.ExpandA(rho);

            (int[][] s1, int[][] s2) = _pseudoRandomSampler.ExpandS(rhoPrim);

            int[][] t = CalcT(aDash, s1, s2);

            (int[][] t1, int[][] t0) = _dilithiumFunctions.Power2Round(t);

            byte[] pk = _encoder.PkEncode(rho, t1);

            byte[] tr = Shake256.HashData(pk, 64);
            DecodedSecretKeyDto skDto = new(Rho: rho, K: k, Tr: tr, S1: s1, S2: s2, T0: t0);

            byte[] sk = _encoder.SkEncode(skDto);

            return (pk, sk);
        }

        /// <summary>
        /// Hashes ξ ‖ IntToBytes(k, 1) ‖ IntToBytes(l, 1) with SHAKE-256 (128 bytes) and
        /// splits the output into ρ (bytes 0–31), ρ' (bytes 32–95), K (bytes 96–127).
        /// </summary>
        private (byte[] rho, byte[] rhoPrim, byte[] k) ExtraxtDataFromSeed(byte[] ksi)
        {
            byte[] hashSource = ByteArrayHelpers.ConcatBytes(
                ksi,
                _bitAlgorithms.IntegerToBytes(_parameters.AMatrixDimensions.K, 1),
                _bitAlgorithms.IntegerToBytes(_parameters.AMatrixDimensions.L, 1)
            );

            byte[] hash = Shake256.HashData(hashSource, 128);

            byte[] rho = new byte[32];
            Buffer.BlockCopy(hash, 0, rho, 0, 32);

            byte[] rhoPrim = new byte[64];
            Buffer.BlockCopy(hash, 32, rhoPrim, 0, 64);

            byte[] k = new byte[32];
            Buffer.BlockCopy(hash, 96, k, 0, 32);

            return (rho, rhoPrim, k);
        }

        /// <summary>
        /// Computes t = NTT⁻¹(Â · NTT(s1)) + s2 in the standard (non-NTT) domain.
        /// </summary>
        private int[][] CalcT(int[][][] aDash, int[][] s1, int[][] s2)
        {
            int[][] s1Dash = Ntt.ForwardNtt(s1);
            int[][] product = _nttArithmetic.MatrixVectorNtt(aDash, s1Dash);
            int[][] reversedNtt = Ntt.InverseNtt(product);
            int[][] t = _nttArithmetic.AddVectorNtt(s2.Length, reversedNtt, s2);

            return t;
        }
    }
}
