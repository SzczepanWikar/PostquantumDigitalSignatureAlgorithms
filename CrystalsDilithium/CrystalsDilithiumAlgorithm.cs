using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Algorithms;
using CrystalsDilithium.Dto;

namespace CrystalsDilithium
{
    public sealed class CrystalsDilithiumAlgorithm
    {
        private readonly DilithiumParameters _parameters;
        private readonly BitAlgorithms _bitAlgorithms;
        private readonly PseudoRandomSampling _pseudoRandomSampling;
        private readonly NttArithmetic _nttArithmetic;
        private readonly Encoding _encoding;
        private readonly DilithiumFunctions _dilithiumFunctions;

        public CrystalsDilithiumAlgorithm(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _bitAlgorithms = new(parameters);
            _pseudoRandomSampling = new(parameters);
            _nttArithmetic = new(parameters);
            _encoding = new(parameters);
            _dilithiumFunctions = new(parameters);
        }

        public (byte[] pk, byte[] sk) KeyGen()
        {
            byte[] bytes = new byte[256];
            RandomNumberGenerator.Fill(bytes);

            (byte[] pk, byte[] sk) = KeyGen(bytes);

            return (pk, sk);
        }

        public (byte[] pk, byte[] sk) KeyGen(byte[] seed)
        {
            if (seed.Length != 256)
            {
                throw new ArgumentException("Seed must be 256 bytes long.");
            }

            (byte[] pk, byte[] sk) = KeyGenInternal(seed);

            return (pk, sk);
        }

        private (byte[] pk, byte[] sk) KeyGenInternal(byte[] ksi)
        {
            (byte[] rho, byte[] rhoPrim, byte[] k) = ExtraxtDataFromSeed(ksi);

            int[][][] aDash = _pseudoRandomSampling.ExpandA(rho);

            (int[][] s1, int[][] s2) = _pseudoRandomSampling.ExpandS(rhoPrim);

            int[][] t = CalcT(aDash, s1, s2);

            (int[][] t1, int[][] t0) = _dilithiumFunctions.Power2Round(t);

            byte[] pk = _encoding.PkEncode(rho, t1);

            byte[] tr = Shake256.HashData(pk, 64);
            DecodedSecretKeyDto skDto = new(Rho: rho, K: k, Tr: tr, S1: s1, S2: s2, T0: t0);

            byte[] sk = _encoding.SkEncode(skDto);

            return (pk, sk);
        }

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

        private int[][] CalcT(int[][][] aDash, int[][] s1, int[][] s2)
        {
            int[][] s1Dash = Ntt.ForwardNtt(s1);
            int[][] product = _nttArithmetic.MatrixVectorNtt(aDash, s1Dash);
            int[][] reversedNtt = Ntt.InverseNtt(product);
            int[][] t = _nttArithmetic.AddVectorNtt(reversedNtt, s2);

            return t;
        }
    }
}
