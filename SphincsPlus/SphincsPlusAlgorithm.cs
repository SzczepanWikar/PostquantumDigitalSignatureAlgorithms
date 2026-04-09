using System.Security.Cryptography;
using Core.Helpers;
using SphincsPlus.Algorithms;
using SphincsPlus.Algorithms.Operations;
using SphincsPlus.Models;

namespace SphincsPlus
{
    public sealed class SphincsPlusAlgorithm
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly KeyGenerator _keyGenerator;
        private readonly Signer _signer;
        private readonly Verifier _verifier;
        private readonly bool _deterministic;

        public SphincsPlusAlgorithm(SphincsPlusParameters parameters, bool deterministic)
        {
            _parameters = parameters;
            _keyGenerator = new(parameters);
            _signer = new(parameters);
            _verifier = new(parameters);
            _deterministic = deterministic;
        }

        public (byte[] sk, byte[] pk) KeyGen()
        {
            byte[] skSeed = new byte[_parameters.N];
            byte[] skPrf = new byte[_parameters.N];
            byte[] pkSeed = new byte[_parameters.N];

            RandomNumberGenerator.Fill(skSeed);
            RandomNumberGenerator.Fill(skPrf);
            RandomNumberGenerator.Fill(pkSeed);

            var (sk, pk) = _keyGenerator.KeyGenInternal(skSeed, skPrf, pkSeed);

            return (sk.ToBytesArray(), pk.ToBytesArray());
        }

        /// <summary>
        /// Algorithm 22 — slh_sign.
        /// </summary>
        public byte[] Sign(byte[] m, byte[] ctx, byte[] sk)
        {
            if (ctx.Length > 255)
            {
                throw new ArgumentException("Context string is too long.");
            }

            byte[]? addRnd = GenerateAddRnd();

            byte[] mPrime = ByteArrayHelpers.ConcatBytes(
                ByteConversions.ToByte(0, 1),
                ByteConversions.ToByte(ctx.Length, 1),
                ctx,
                m
            );

            return _signer.SignInternal(mPrime, SecretKey.FromBytesArray(sk), addRnd);
        }

        /// <summary>
        /// Algorithm 23 — hash_slh_sign.
        /// </summary>
        public byte[] Sign(byte[] m, byte[] ctx, PreHashFunction ph, byte[] sk)
        {
            if (ctx.Length > 255)
            {
                throw new ArgumentException("Context string is too long.");
            }

            byte[]? addRnd = GenerateAddRnd();

            var (oid, phM) = PreHashMessage(m, ph);

            byte[] mPrime = ByteArrayHelpers.ConcatBytes(
                ByteConversions.ToByte(1, 1),
                ByteConversions.ToByte(ctx.Length, 1),
                ctx,
                oid,
                phM
                );

            byte[] signature = _signer.SignInternal(mPrime, SecretKey.FromBytesArray(sk), addRnd);

            return signature;
        }

        private byte[]? GenerateAddRnd()
        {
            if (_deterministic)
            {
                return null;
            }
            
            byte[] addRnd = new byte[_parameters.N];
            RandomNumberGenerator.Fill(addRnd);

            return addRnd;
        }

        private (byte[] oid, byte[] phM) PreHashMessage(byte[] msg, PreHashFunction preHashFunction)
        {
            return preHashFunction switch
            {
                PreHashFunction.Sha256 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                    SHA256.HashData(msg)
                ),
                PreHashFunction.Sha512 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
                    SHA512.HashData(msg)
                ),
                PreHashFunction.Shake128 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
                    Shake128.HashData(msg, 32)
                ),
                PreHashFunction.Shake256 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
                    Shake256.HashData(msg, 64)
                ),
            };
        }
    }
}

