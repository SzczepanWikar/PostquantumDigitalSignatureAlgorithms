using Core.Helpers;
using CrystalsDilithium.Dto;
using System.Collections;
using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace CrystalsDilithium
{
    internal sealed class Encoding
    {
        private readonly byte _precalcedBitlen;
        private readonly byte _precalcedPowerOfTwo;
        private readonly byte _twoToPowerOfDMinusOne;

        private readonly DilithiumParameters _parameters;
        private readonly BitAlgorithms _bitAlgorithms;

        public Encoding(DilithiumParameters parameters)
        {
            _parameters = parameters;
            _precalcedBitlen = (byte)(BitLength.GetNumberBitLength(DilithiumParameters.Q - 1) - parameters.D);
            _precalcedPowerOfTwo = (byte)(1 << _precalcedBitlen);
            _bitAlgorithms = new BitAlgorithms(parameters);
            _twoToPowerOfDMinusOne = (byte)(1 << (_parameters.D - 1));
        }

        public byte[] PkEncode(byte[] rho, int[][] t1)
        {
            Debug.Assert(rho.Length == 32, "Rho must be 32 bytes long.");

            IEnumerable<byte> pk = new byte[32];
            pk = pk.Concat(rho);

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                pk = pk.Concat(_bitAlgorithms.SimpleBitPack(t1[i], _precalcedPowerOfTwo - 1));
            }

            return pk.ToArray();
        }

        public (byte[] rho, int[][] t1) PkDecode(byte[] pk) 
        {
            byte[] rho = pk.Take(32).ToArray();
            int[][] t1 = new int[_parameters.AMatrixDimensions.K][];

            int offset = 32;

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                int ziBytes = 32 * _precalcedBitlen / 8;

                byte[] zi = new byte[ziBytes];
                Buffer.BlockCopy(pk, offset, zi, 0, ziBytes);
                offset += ziBytes;

                t1[i] = _bitAlgorithms.SimpleBitUnpack(zi, _precalcedBitlen);
            }

            return (rho, t1);
        }

        public byte[] SkEncode(SignatureKeyDto dto)
        {
            IEnumerable<byte> sk = dto.Rho.Concat(dto.K).Concat(dto.Tr);

            foreach (int[] s in dto.S1)
            {
                sk = sk.Concat(_bitAlgorithms.BitPack(s, _parameters.Eta, _parameters.Eta));
            }

            foreach (int[] s in dto.S2)
            {
                sk = sk.Concat(_bitAlgorithms.BitPack(s, _parameters.Eta, _parameters.Eta));
            }


            foreach (int[] s in dto.T0)
            {
                sk = sk.Concat(_bitAlgorithms.BitPack(s, _twoToPowerOfDMinusOne - 1, _twoToPowerOfDMinusOne));
            }

            return sk.ToArray();
        }

        public SignatureKeyDto SkDecode(byte[] sk)
        {
            int bitLenEta = BitLength.GetBitLength(2 * _parameters.Eta);   // bitlen(2η)
            int yiBytes = 32 * bitLenEta / 8;
            int wiBytes = 32 * _parameters.D / 8;

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

            int[][] s1 = new int[_parameters.AMatrixDimensions.K][];
            int[][] s2 = new int[_parameters.AMatrixDimensions.K][];
            int[][] t0 = new int[_parameters.AMatrixDimensions.K][];

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                byte[] yi = new byte[yiBytes];
                Buffer.BlockCopy(sk, offset, yi, 0, yiBytes);
                offset += yiBytes;

                s1[i] = _bitAlgorithms.BitUnpack(yi, bitLenEta, _parameters.Eta);
            }

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                byte[] zi = new byte[yiBytes];
                Buffer.BlockCopy(sk, offset, zi, 0, yiBytes);
                offset += yiBytes;

                s2[i] = _bitAlgorithms.BitUnpack(zi, bitLenEta, _parameters.Eta);
            }

            for (int i = 0; i < _parameters.AMatrixDimensions.K; i++)
            {
                byte[] wi = new byte[wiBytes];
                Buffer.BlockCopy(sk, offset, wi, 0, wiBytes);
                offset += wiBytes;


                t0[i] = _bitAlgorithms.BitUnpack(wi, _twoToPowerOfDMinusOne - 1, _twoToPowerOfDMinusOne);
            }

            return new (rho, K, tr, s1, s2, t0);
        }

        public byte[] SigEncode(SignatureDto dto)
        {
            int l = dto.Z.Length;
            int bitLen = BitLength.GetBitLength(_parameters.Gamma1 - 1);

            int ziBytes = 32 * bitLen / 8;
            byte[] hint = _bitAlgorithms.HintBitPack(dto.H);

            int totalSize = dto.CWave.Length + l * ziBytes + hint.Length;
            byte[] sigma = new byte[totalSize];

            int offset = 0;

            Buffer.BlockCopy(dto.CWave, 0, sigma, offset, dto.CWave.Length);
            offset += dto.CWave.Length;

            for (int i = 0; i < l; i++)
            {
                byte[] zi = _bitAlgorithms.BitPack(dto.Z[i], _parameters.Gamma1 - 1, _parameters.Gamma1);
                Buffer.BlockCopy(zi, 0, sigma, offset, zi.Length);
                offset += zi.Length;
            }

            Buffer.BlockCopy(hint, 0, sigma, offset, hint.Length);
            return sigma;
        }


        public SignatureDto SigDecode(byte[] sigma)
        {
            int l = _parameters.AMatrixDimensions.L;
            int bitLen = BitLength.GetBitLength(_parameters.Gamma1 - 1);

            int ziBytes = 32 * bitLen / 8;
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

            int remaining = sigma.Length - offset;
            byte[] hintBytesArr = new byte[remaining];
            Buffer.BlockCopy(sigma, offset, hintBytesArr, 0, remaining);

            IList<BitArray>? h = _bitAlgorithms.HintBitUnpack(hintBytesArr);

            if(h == null)
            {
                throw new Exception("Invalid hint");
            }

            return new(cWave, z, h);
        }

        public byte[] W1Encode(int[][] w1)
        {
            int k = _parameters.AMatrixDimensions.K;

            int max = (DilithiumParameters.Q - 1) / (2 * _parameters.Gamma2) - 1;
            int bitLen = BitLength.GetBitLength(max);

            int polyBytes = 32 * bitLen / 8;
            byte[] w1hat = new byte[k * polyBytes];

            int offset = 0;

            for (int i = 0; i < k; i++)
            {
                foreach (int coeff in w1[i])
                {
                    if (coeff < 0 || coeff > max)
                        throw new CryptographicException("w1 coefficient out of range");
                }

                byte[] packed = _bitAlgorithms.SimpleBitPack(w1[i], max);
                Buffer.BlockCopy(packed, 0, w1hat, offset, packed.Length);
                offset += packed.Length;
            }

            return w1hat;
        }

    }
}
