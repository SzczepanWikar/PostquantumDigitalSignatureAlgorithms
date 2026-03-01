using System.Collections;
using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Dto;

namespace CrystalsDilithium.Algorithms.Operations
{
    internal sealed class Signer
    {
        private readonly DilithiumParameters _parameters;
        private readonly Encoding _encoder;
        private readonly PseudoRandomSampling _pseudoRandomSampler;
        private readonly BitAlgorithms _bitAlgorithms;
        private readonly NttArithmetic _nttArithmetic;
        private readonly DilithiumFunctions _dilithiumFunctions;

        public Signer(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _encoder = new(parameters);
            _pseudoRandomSampler = new(parameters);
            _bitAlgorithms = new(parameters);
            _nttArithmetic = new(parameters);
            _dilithiumFunctions = new(parameters);
        }

        public byte[] SignInternal(byte[] sk, BitArray message, byte[] rnd)
        {
            DecodedSecretKeyDto decodedSk = _encoder.SkDecode(sk);
            int[][] s1Hat = Ntt.ForwardNtt(decodedSk.S1);
            int[][] s2Hat = Ntt.ForwardNtt(decodedSk.S2);
            int[][] t0Hat = Ntt.ForwardNtt(decodedSk.T0);
            int[][][] aHat = _pseudoRandomSampler.ExpandA(decodedSk.Rho);

            (byte[] mi, byte[] rhoBis) = GeneratePrivateRandomSeed(decodedSk, message, rnd);

            int k = 0;

            int[][]? z = null;
            BitArray[]? h = null;
            byte[] cWave = [];

            while (z is null)
            {
                int[][] y = _pseudoRandomSampler.ExpandMask(rhoBis, k);

                int[][] w = Ntt.InverseNtt(_nttArithmetic.MatrixVectorNtt(aHat, Ntt.ForwardNtt(y)));
                int[][] w1 = _dilithiumFunctions.HighBits(w);
                cWave = Shake256.HashData(
                    ByteArrayHelpers.ConcatBytes(mi, _encoder.W1Encode(w1)),
                    _parameters.Lambda / 4
                );
                int[] c = _pseudoRandomSampler.SampleInBall(cWave);
                int[] cHat = Ntt.ForwardNtt(c);
                int[][] cs1Norm = Ntt.InverseNtt(
                    _nttArithmetic.ScalarVectorNtt(_parameters.AMatrixDimensions.L, cHat, s1Hat)
                );
                int[][] cs2Norm = Ntt.InverseNtt(
                    _nttArithmetic.ScalarVectorNtt(_parameters.AMatrixDimensions.K, cHat, s2Hat)
                );

                (z, h) = SampleZAndH(t0Hat, y, w, cHat, cs1Norm, cs2Norm);

                k += _parameters.AMatrixDimensions.L;
            }

            SignatureDto dto = new(CWave: cWave, Z: CalcModulo(z!), H: h!);

            byte[] sigma = _encoder.SigEncode(dto);

            return sigma;
        }

        private (int[][]? z, BitArray[]? h) SampleZAndH(
            int[][] t0Hat,
            int[][] y,
            int[][] w,
            int[] cHat,
            int[][] cs1Norm,
            int[][] cs2Norm
        )
        {
            int[][]? z = null;
            BitArray[]? h = null;

            z = _nttArithmetic.AddVectorNtt(y.Length, y, cs1Norm);
            int[][] r0 = _dilithiumFunctions.LowBits(
                _nttArithmetic.SubtractVectorNtt(w.Length, w, cs2Norm)
            );

            int zInfiniteNorm = PolynomialNorm.InfinityNorm(z, DilithiumParameters.Q);
            int r0InfiniteNorm = PolynomialNorm.InfinityNorm(r0, DilithiumParameters.Q);

            if (
                zInfiniteNorm >= _parameters.Gamma1 - _parameters.Beta
                || r0InfiniteNorm >= _parameters.Gamma2 - _parameters.Beta
            )
            {
                return (null, null);
            }

            int[][] ct0Norm = Ntt.InverseNtt(
                _nttArithmetic.ScalarVectorNtt(_parameters.AMatrixDimensions.K, cHat, t0Hat)
            );

            int ct0NormInfiniteNorm = PolynomialNorm.InfinityNorm(ct0Norm, DilithiumParameters.Q);

            if (ct0NormInfiniteNorm >= _parameters.Gamma2)
            {
                return (null, null);
            }

            h = CalcHint(w, cs2Norm, ct0Norm);

            if (BitArrayHelpers.CountTruths(h) > _parameters.Omega)
            {
                return (null, null);
            }

            return (z, h);
        }

        private (byte[] mi, byte[] rhoBis) GeneratePrivateRandomSeed(
            DecodedSecretKeyDto decodedSk,
            BitArray message,
            byte[] rnd
        )
        {
            BitArray trBits = _bitAlgorithms.BytesToBits(decodedSk.Tr);
            BitArray concatedMessage = BitArrayHelpers.Concat(trBits, message);
            byte[] packedMessage = _bitAlgorithms.BitsToBytes(concatedMessage);
            byte[] mi = Shake256.HashData(packedMessage, 64);

            byte[] rhoBisContent = ByteArrayHelpers.ConcatBytes(decodedSk.K, rnd, mi);
            byte[] rhoBis = Shake256.HashData(rhoBisContent, 64);

            return (mi, rhoBis);
        }

        private int[][] CalcModulo(int[][] z)
        {
            int[][] res = new int[z.Length][];

            for (int i = 0; i < z.Length; i++)
            {
                res[i] = new int[z[i].Length];

                for (int j = 0; j < z[i].Length; j++)
                {
                    res[i][j] = Modulo.ModPlusMinus(z[i][j], DilithiumParameters.Q);
                }
            }

            return res;
        }

        private BitArray[] CalcHint(int[][] w, int[][] cs2Norm, int[][] ct0Norm)
        {
            int[][] r = _nttArithmetic.AddVectorNtt(
                _parameters.AMatrixDimensions.K,
                _nttArithmetic.SubtractVectorNtt(_parameters.AMatrixDimensions.K, w, cs2Norm),
                ct0Norm
            );

            return _dilithiumFunctions.MakeHint(_nttArithmetic.ReverseVectorNtt(ct0Norm), r);
        }
    }
}
