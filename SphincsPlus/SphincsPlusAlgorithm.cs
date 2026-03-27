using SphincsPlus.Algorithms.Operations;
using SphincsPlus.Models;
using System.Security.Cryptography;

namespace SphincsPlus
{
    public sealed class SphincsPlusAlgorithm
    {
        private readonly SphincsPlusParameters _parameters;
        private readonly KeyGenerator _keyGenerator;
        public SphincsPlusAlgorithm(SphincsPlusParameters parameters) 
        {
            _parameters = parameters;
            _keyGenerator = new (parameters);
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
    }
}
