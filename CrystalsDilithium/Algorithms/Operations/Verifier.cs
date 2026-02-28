using System.Collections;
using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Dto;

namespace CrystalsDilithium.Algorithms.Operations
{
    internal sealed class Verifier
    {
        private readonly DilithiumParameters _parameters;
        private readonly Encoding _encoder;
        private readonly BitAlgorithms _bitAlgorithms;
        private readonly DilithiumFunctions _dilithiumFunctions;
        private readonly PseudoRandomSampling _pseudoRandomSampler;
        private readonly NttArithmetic _nttArithmetic;

        public Verifier(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _encoder = new(parameters);
            _bitAlgorithms = new(parameters);
            _dilithiumFunctions = new(parameters);
            _pseudoRandomSampler = new(parameters);
            _nttArithmetic = new(parameters);
        }

        public bool VerifyInternal(byte[] pk, BitArray mPrim, byte[] sigma)
        {
            var (rho, t1) = _encoder.PkDecode(pk);
            SignatureDto dto = _encoder.SigDecode(sigma);

            if (dto.H == null)
            {
                return false;
            }

            byte[] tr = Shake256.HashData(pk, 64);
            byte[] mi = CalcMi(mPrim, tr);
            int[][][] aHat = _pseudoRandomSampler.ExpandA(rho);

            int[] c = _pseudoRandomSampler.SampleInBall(dto.CWave);
            int[][] az = _nttArithmetic.MatrixVectorNtt(aHat, Ntt.ForwardNtt(dto.Z));

            int[][] aproxedWPrim = CalcApproximatedW1Prim(t1, c, az);
            int[][] wPrim = _dilithiumFunctions.UseHint(dto.H, aproxedWPrim);
            byte[] cWavePrim = CalcCWave(mi, wPrim);
            int zInfiniteNorm = PolynomialNorm.InfinityNorm(dto.Z, DilithiumParameters.Q);

            return zInfiniteNorm < _parameters.Gamma1 - _parameters.Beta
                && cWavePrim.SequenceEqual(dto.CWave);
        }

        private byte[] CalcMi(BitArray mPrim, byte[] tr)
        {
            BitArray trBits = new BitArray(tr);
            BitArray hashContentBits = BitArrayHelpers.Concat(trBits, mPrim);
            byte[] hashContent = _bitAlgorithms.BitsToBytes(hashContentBits);
            byte[] mi = Shake256.HashData(hashContent, 64);

            return mi;
        }

        private int[][] CalcApproximatedW1Prim(int[][] t1, int[] c, int[][] az) =>
            Ntt.InverseNtt(
                _nttArithmetic.SubtractVectorNtt(
                    az.Length,
                    az,
                    _nttArithmetic.ScalarVectorNtt(t1.Length, Ntt.ForwardNtt(c), CalcT1(t1))
                )
            );

        private int[][] CalcT1(int[][] t1)
        {
            int[][] res = new int[t1.Length][];

            for (int i = 0; i < t1.Length; i++)
            {
                res[i] = new int[t1[i].Length];

                for (int j = 0; j < t1[i].Length; j++)
                {
                    res[i][j] = t1[i][j] << _parameters.D;
                }
            }

            return Ntt.ForwardNtt(res);
        }

        private byte[] CalcCWave(byte[] mi, int[][] wPrim) =>
            Shake256.HashData(
                ByteArrayHelpers.ConcatBytes(mi, _encoder.W1Encode(wPrim)),
                _parameters.Lambda / 4
            );
    }
}
