using System.Collections;
using System.Diagnostics;
using System.Security.Cryptography;
using Core.Helpers;
using CrystalsDilithium.Dto;

namespace CrystalsDilithium.Algorithms
{
    internal sealed class Encoding
    {
        private readonly byte _precalcedBitlen;
        private readonly int _precalcedPowerOfTwo;
        private readonly int _twoToPowerOfDMinusOne;

        private readonly DilithiumParameters _parameters;
        private readonly BitAlgorithms _bitAlgorithms;

        public Encoding(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _precalcedBitlen = (byte)(
                BitLength.GetNumberBitLength(DilithiumParameters.Q - 1) - parameters.D
            );
            _precalcedPowerOfTwo = 1 << _precalcedBitlen;
            _bitAlgorithms = new BitAlgorithms(parameters);
            _twoToPowerOfDMinusOne = 1 << (_parameters.D - 1);
        }

        public byte[] PkEncode(byte[] rho, int[][] t1)
        {
            Debug.Assert(rho.Length == 32, "Rho must be 32 bytes long.");

            byte[] pk = new byte[32];
            Buffer.BlockCopy(rho, 0, pk, 0, 32);

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                pk = ByteArrayHelpers.ConcatBytes(
                    pk,
                    _bitAlgorithms.SimpleBitPack(t1[i], _precalcedPowerOfTwo - 1)
                );
            }

            return pk;
        }

        public (byte[] rho, int[][] t1) PkDecode(byte[] pk)
        {
            byte[] rho = pk.Take(32).ToArray();
            int[][] t1 = new int[_parameters.AMatrixDimensions.K][];

            int offset = 32;

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                int ziBytes = 32 * _precalcedBitlen;

                byte[] zi = new byte[ziBytes];
                Buffer.BlockCopy(pk, offset, zi, 0, ziBytes);
                offset += ziBytes;

                t1[i] = _bitAlgorithms.SimpleBitUnpack(zi, _precalcedPowerOfTwo - 1);
            }

            return (rho, t1);
        }

        public byte[] SkEncode(DecodedSecretKeyDto dto)
        {
            byte[] sk = ByteArrayHelpers.ConcatBytes(dto.Rho, dto.K, dto.Tr);

            foreach (int[] s in dto.S1)
            {
                sk = ByteArrayHelpers.ConcatBytes(
                    sk,
                    _bitAlgorithms.BitPack(s, _parameters.Eta, _parameters.Eta)
                );
            }

            foreach (int[] s in dto.S2)
            {
                sk = ByteArrayHelpers.ConcatBytes(
                    sk,
                    _bitAlgorithms.BitPack(s, _parameters.Eta, _parameters.Eta)
                );
            }

            foreach (int[] s in dto.T0)
            {
                sk = ByteArrayHelpers.ConcatBytes(
                    sk,
                    _bitAlgorithms.BitPack(s, _twoToPowerOfDMinusOne - 1, _twoToPowerOfDMinusOne)
                );
            }

            return sk.ToArray();
        }

        public DecodedSecretKeyDto SkDecode(byte[] sk)
        {
            int bitLenEta = BitLength.GetBitLength(2 * _parameters.Eta); // bitlen(2η)
            int yiBytes = 32 * bitLenEta;
            int wiBytes = 32 * _parameters.D;

            int offset = 0;

            byte[] rho = new byte[32];
            Buffer.BlockCopy(sk, offset, rho, 0, 32);
            offset += 32;

            byte[] K = new byte[32];
            Buffer.BlockCopy(sk, offset, K, 0, 32);
            offset += 32;

            byte[] tr = new byte[64];
            Buffer.BlockCopy(sk, offset, tr, 0, 64);
            offset += 64;

            int[][] s1 = new int[_parameters.AMatrixDimensions.L][];
            int[][] s2 = new int[_parameters.AMatrixDimensions.K][];
            int[][] t0 = new int[_parameters.AMatrixDimensions.K][];

            for (int i = 0; i < _parameters.AMatrixDimensions.L; i++)
            {
                byte[] yi = new byte[yiBytes];
                Buffer.BlockCopy(sk, offset, yi, 0, yiBytes);
                offset += yiBytes;

                s1[i] = _bitAlgorithms.BitUnpack(yi, _parameters.Eta, _parameters.Eta);
            }

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                byte[] zi = new byte[yiBytes];
                Buffer.BlockCopy(sk, offset, zi, 0, yiBytes);
                offset += yiBytes;

                s2[i] = _bitAlgorithms.BitUnpack(zi, _parameters.Eta, _parameters.Eta);
            }

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                byte[] wi = new byte[wiBytes];
                Buffer.BlockCopy(sk, offset, wi, 0, wiBytes);
                offset += wiBytes;

                t0[i] = _bitAlgorithms.BitUnpack(
                    wi,
                    _twoToPowerOfDMinusOne - 1,
                    _twoToPowerOfDMinusOne
                );
            }

            return new(rho, K, tr, s1, s2, t0);
        }

        public byte[] SigEncode(SignatureDto dto)
        {
            int l = dto.Z.Length;
            int bitLen = BitLength.GetBitLength(_parameters.Gamma1 - 1);

            byte[] sigma = new byte[dto.CWave.Length];
            Buffer.BlockCopy(dto.CWave, 0, sigma, 0, dto.CWave.Length);

            for (int i = 0; i < l; i++)
            {
                byte[] zi = _bitAlgorithms.BitPack(
                    dto.Z[i],
                    _parameters.Gamma1 - 1,
                    _parameters.Gamma1
                );

                sigma = ByteArrayHelpers.ConcatBytes(sigma, zi);
            }

            byte[] hint = _bitAlgorithms.HintBitPack(dto.H);
            sigma = ByteArrayHelpers.ConcatBytes(sigma, hint);

            return sigma;
        }

        public SignatureDto SigDecode(byte[] sigma)
        {
            int l = _parameters.AMatrixDimensions.L;
            int bitLen = BitLength.GetBitLength(2 * _parameters.Gamma1 - 1);

            int ziBytes = 32 * bitLen;
            int cBytes = _parameters.Lambda / 4;
            int hintBytes = _parameters.Omega + _parameters.AMatrixDimensions.K;

            int offset = 0;

            byte[] cWave = new byte[cBytes];
            Buffer.BlockCopy(sigma, offset, cWave, 0, cBytes);
            offset += cBytes;

            int[][] z = new int[l][];

            for (int i = 0; i < l; i++)
            {
                byte[] zi = new byte[ziBytes];
                Buffer.BlockCopy(sigma, offset, zi, 0, ziBytes);
                offset += ziBytes;

                z[i] = _bitAlgorithms.BitUnpack(zi, _parameters.Gamma1 - 1, _parameters.Gamma1);
            }

            if (sigma.Length - offset != hintBytes)
            {
                throw new CryptographicException("Invalid signature length");
            }

            byte[] hintBytesArr = new byte[hintBytes];
            Buffer.BlockCopy(sigma, offset, hintBytesArr, 0, hintBytes);

            BitArray[]? h = _bitAlgorithms.HintBitUnpack(hintBytesArr);

            return new(cWave, z, h);
        }

        public byte[] W1Encode(int[][] w1)
        {
            int k = _parameters.AMatrixDimensions.K;

            int max = (DilithiumParameters.Q - 1) / (2 * _parameters.Gamma2) - 1;
            int bitLen = BitLength.GetBitLength(max);

            int polyBytes = 32 * bitLen;
            byte[] w1hat = new byte[k * polyBytes];

            int offset = 0;

            for (int i = 0; i < k; i++)
            {
                foreach (int coeff in w1[i])
                {
                    if (coeff < 0 || coeff > max)
                    {
                        throw new CryptographicException("w1 coefficient out of range");
                    }
                }

                byte[] packed = _bitAlgorithms.SimpleBitPack(w1[i], max);
                Buffer.BlockCopy(packed, 0, w1hat, offset, packed.Length);
                offset += packed.Length;
            }

            return w1hat;
        }
    }
}
