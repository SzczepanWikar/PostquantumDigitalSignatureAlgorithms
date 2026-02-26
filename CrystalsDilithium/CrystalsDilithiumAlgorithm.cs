using System.Collections;
using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Algorithms;
using CrystalsDilithium.Algorithms.Operations;

namespace CrystalsDilithium
{
    public sealed class CrystalsDilithiumAlgorithm
    {
        private const byte _seedLength = 32;
        private readonly DilithiumParameters _parameters;
        private readonly KeyGenerator _keyGenerator;
        private readonly Signer _signer;
        private readonly BitAlgorithms _bitAlgorithms;

        public CrystalsDilithiumAlgorithm(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _keyGenerator = new(parameters);
            _signer = new(parameters);
            _bitAlgorithms = new(parameters);
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

        public byte[] Sign(byte[] sk, BitArray m) => Sign(sk, m, []);

        public byte[] Sign(byte[] sk, byte[] m) => Sign(sk, m, []);

        public byte[] Sign(byte[] sk, byte[] m, byte[] ctx)
        {
            BitArray message = _bitAlgorithms.BytesToBits(m);

            return Sign(sk, message, ctx);
        }

        public byte[] Sign(byte[] sk, BitArray m, byte[] ctx)
        {
            if (ctx.Length > 255)
            {
                throw new ArgumentException("Context string is to long.");
            }

            byte[] rnd = RandomNumberGenerator.GetBytes(32);

            byte[] messagePrefix = ByteArrayHelpers.ConcatBytes(
                _bitAlgorithms.IntegerToBytes(0, 1),
                _bitAlgorithms.IntegerToBytes(ctx.Length, 1),
                ctx
            );

            BitArray messagePrim = BitArrayHelpers.Concat(
                _bitAlgorithms.BytesToBits(messagePrefix),
                m
            );

            byte[] sigma = _signer.SignInternal(sk, messagePrim, rnd);

            return sigma;
        }
    }
}
