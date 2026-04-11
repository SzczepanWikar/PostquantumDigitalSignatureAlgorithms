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
        private readonly KeyGenerator _keyGenerator;
        private readonly Signer _signer;
        private readonly BitAlgorithms _bitAlgorithms;
        private readonly Verifier _verifier;

        public CrystalsDilithiumAlgorithm(DilithiumParameters parameters)
        {
            _keyGenerator = new(parameters);
            _signer = new(parameters);
            _bitAlgorithms = new(parameters);
            _verifier = new(parameters);
        }

        /// <summary>
        /// Algorithm 1 — ML-DSA.KeyGen. Generates a key pair from a freshly sampled
        /// 32-byte random seed. Delegates to <see cref="KeyGen(byte[])"/>.
        /// </summary>
        public (byte[] pk, byte[] sk) KeyGen()
        {
            byte[] bytes = new byte[_seedLength];
            RandomNumberGenerator.Fill(bytes);

            (byte[] pk, byte[] sk) = KeyGen(bytes);

            return (pk, sk);
        }

        /// <summary>
        /// Algorithm 1 — ML-DSA.KeyGen. Generates a key pair from the provided 32-byte
        /// <paramref name="seed"/> (ξ). Delegates to ML-DSA.KeyGen_internal.
        /// </summary>
        public (byte[] pk, byte[] sk) KeyGen(byte[] seed)
        {
            if (seed.Length != _seedLength)
            {
                throw new ArgumentException($"Seed must be {_seedLength} bytes long.");
            }

            (byte[] pk, byte[] sk) = _keyGenerator.KeyGenInternal(seed);

            return (pk, sk);
        }

        /// <summary>
        /// Algorithm 2 — ML-DSA.Sign. Signs bit-string message <paramref name="m"/> with an
        /// empty context string. Delegates to <see cref="Sign(byte[], BitArray, byte[])"/>.
        /// </summary>
        public byte[] Sign(byte[] sk, BitArray m) => Sign(sk, m, []);

        /// <summary>
        /// Algorithm 2 — ML-DSA.Sign. Signs byte-string message <paramref name="m"/> with an
        /// empty context string. Delegates to <see cref="Sign(byte[], byte[], byte[])"/>.
        /// </summary>
        public byte[] Sign(byte[] sk, byte[] m) => Sign(sk, m, []);

        /// <summary>
        /// Algorithm 2 — ML-DSA.Sign. Converts <paramref name="m"/> to bits and delegates to
        /// <see cref="Sign(byte[], BitArray, byte[])"/>.
        /// </summary>
        public byte[] Sign(byte[] sk, byte[] m, byte[] ctx)
        {
            BitArray message = _bitAlgorithms.BytesToBits(m);

            return Sign(sk, message, ctx);
        }

        /// <summary>
        /// Algorithm 2 — ML-DSA.Sign. Builds the padded message M' = 0x00 ‖ |ctx| ‖ ctx ‖ M,
        /// samples a fresh 32-byte randomness rnd, and calls ML-DSA.Sign_internal(sk, M', rnd).
        /// Throws if |ctx| > 255.
        /// </summary>
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

        /// <summary>
        /// Algorithm 3 — ML-DSA.Verify. Verifies signature <paramref name="sigma"/> for
        /// bit-string message <paramref name="m"/> with an empty context string.
        /// Delegates to <see cref="Verify(byte[], BitArray, byte[], byte[])"/>.
        /// </summary>
        public bool Verify(byte[] pk, BitArray m, byte[] sigma) => Verify(pk, m, sigma, []);

        /// <summary>
        /// Algorithm 3 — ML-DSA.Verify. Verifies signature <paramref name="sigma"/> for
        /// byte-string message <paramref name="m"/> with an empty context string.
        /// Delegates to <see cref="Verify(byte[], byte[], byte[], byte[])"/>.
        /// </summary>
        public bool Verify(byte[] pk, byte[] m, byte[] sigma) => Verify(pk, m, sigma, []);

        /// <summary>
        /// Algorithm 3 — ML-DSA.Verify. Converts <paramref name="m"/> to bits and delegates to
        /// <see cref="Verify(byte[], BitArray, byte[], byte[])"/>.
        /// </summary>
        public bool Verify(byte[] pk, byte[] m, byte[] sigma, byte[] ctx)
        {
            BitArray message = _bitAlgorithms.BytesToBits(m);

            return Verify(pk, message, sigma, ctx);
        }

        /// <summary>
        /// Algorithm 3 — ML-DSA.Verify. Builds the padded message M' = 0x00 ‖ |ctx| ‖ ctx ‖ M
        /// and calls ML-DSA.Verify_internal(pk, M', σ). Returns <see langword="false"/> if
        /// |ctx| > 255. Returns <see langword="true"/> iff the signature is valid.
        /// </summary>
        public bool Verify(byte[] pk, BitArray m, byte[] sigma, byte[] ctx)
        {
            if (ctx.Length > 255)
            {
                throw new ArgumentException("Context string is to long.");
            }

            byte[] messagePrefix = ByteArrayHelpers.ConcatBytes(
                _bitAlgorithms.IntegerToBytes(0, 1),
                _bitAlgorithms.IntegerToBytes(ctx.Length, 1),
                ctx
            );

            BitArray messagePrim = BitArrayHelpers.Concat(
                _bitAlgorithms.BytesToBits(messagePrefix),
                m
            );

            bool res = _verifier.VerifyInternal(pk, messagePrim, sigma);

            return res;
        }
    }
}
