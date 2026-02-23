using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Algorithms;
using CrystalsDilithium.Algorithms.Operations;
using CrystalsDilithium.Dto;

namespace CrystalsDilithium
{
    public sealed class CrystalsDilithiumAlgorithm
    {
        private const byte _seedLength = 32;
        private readonly DilithiumParameters _parameters;
        private readonly KeyGenerator _keyGenerator;

        public CrystalsDilithiumAlgorithm(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _keyGenerator = new(parameters);
        }

        public (byte[] pk, byte[] sk) KeyGen()
        {
            byte[] bytes = new byte[_seedLength];
            RandomNumberGenerator.Fill(bytes);

            (byte[] pk, byte[] sk) = KeyGen(bytes);

            return (pk, sk);
        }

        public (byte[] pk, byte[] sk) KeyGen(byte[] seed)
        {
            if (seed.Length != _seedLength)
            {
                throw new ArgumentException($"Seed must be {_seedLength} bytes long.");
            }

            (byte[] pk, byte[] sk) = _keyGenerator.KeyGenInternal(seed);

            return (pk, sk);
        }
    }
}
