using Core.Helpers;
using System.Collections;
using System.Diagnostics;

namespace CrystalsDilithium
{
    internal class BitAlgorithms
    {
        private readonly DilithiumParameters _parameters;
        public BitAlgorithms(DilithiumParameters parameters)
        {
            _parameters = parameters;
        }
        public BitArray IntegerToBits(int x, int alpha)
        {
            Debug.Assert(x >= 0, "Input must be non-negative.");
            Debug.Assert(alpha > 0, "Bit length must be positive.");

            IEnumerable<bool> bits = new BitArray(new[] { x }).Cast<bool>().Take(alpha);

            return new BitArray(bits.ToArray());
        }

        public int BitsToInteger(BitArray y, int alpha)
        {
            Debug.Assert(y.Length > 0, "Bit array must not be empty.");
            Debug.Assert(alpha > 0, "Bit length must be positive.");
            Debug.Assert(y.Length >= alpha, "Bit array length must be at least as long as the specified bit length.");

            int result = 0;

            for (int i = 0; i < alpha; i++)
            {
                result = 2 * result + (y[i].ToInt32());
            }

            return result;
        }

        public byte[] IntegerToBytes(int x, int alpha)
        {
            Debug.Assert(x >= 0, "Input must be non-negative.");
            Debug.Assert(alpha > 0, "Byte count must be positive.");

            byte[] bytes = new byte[alpha];
            for (int i = 0; i < alpha; i++)
            {
                bytes[i] = (byte)(x % 256);
                x /= 256;
            }

            return bytes;
        }

        public byte[] BitsToBytes(BitArray y)
        {
            Debug.Assert(y.Length > 0, "Bit array must not be empty.");

            int byteCount = y.Length / 8;
            byte[] bytes = new byte[byteCount];

            for (int i = 0; i < y.Length; i++)
            {
                bytes[i / 8] = (byte)(bytes[i / 8] + y[i].ToByte() * (1 << (i % 8)));
            }

            return bytes;
        }

        public BitArray BytesToBits(byte[] z) => new BitArray(z);

        public int? CoeffFromThreeBytes(byte b0, byte b1, byte b2)
        {
            if (b2 > 127)
            {
                b2 -= 128;
            }

            int z = (1 << 16) * b2 + (1 << 8) * b1 + b0;

            if (z < DilithiumParameters.Q)
            {
                return z;
            }

            return null;
        }

        public int? CoeffFromHalfByte(byte b)
        {
            Debug.Assert(b <= 15, "Input must be a half byte (0-15).");

            if (_parameters.Eta == 2 && b < 15)
            {
                return _parameters.Eta - (b % 5);
            }

            if (_parameters.Eta == 4 && b < 9)
            {
                return _parameters.Eta - b;
            }

            return null;
        }

        public byte[] SimpleBitPack(int[] w, int b)
        {
            Debug.Assert(w.Length > 0, "Input array must not be empty.");
            Debug.Assert(b > 0, "Bit length must be positive.");

            BitArray bits = new(0);

            for (int i = 0; i < 255; i++)
            {
                bits = BitArrayHelpers.Concat(bits, IntegerToBits(w[i], b.GetBitLength()));
            }

            return BitsToBytes(bits);
        }

        public byte[] BitPack(int[] w, int a, int b)
        {
            Debug.Assert(w.Length > 0, "Input array must not be empty.");

            BitArray bits = new(0);
            for (int i = 0; i < 255; i++)
            {
                bits = BitArrayHelpers.Concat(bits, IntegerToBits(w[i], (a + b).GetBitLength()));
            }

            return BitsToBytes(bits);
        }

        public int[] SimpleBitUnpack(byte[] v, int b)
        {
            short c = b.GetBitLength();
            BitArray z = BytesToBits(v);

            int[] w = new int[256];

            for (int i = 0; i < 255; i++)
            {
                w[i] = UnpackCoefficient(c, z, i);
            }

            return w;
        }

        public int[] BitUnpack(byte[] v, int a, int b)
        {
            short c = (a + b).GetBitLength();
            BitArray z = BytesToBits(v);

            int[] w = new int[256];

            for (int i = 0; i < 255; i++)
            {
                w[i] = b - UnpackCoefficient(c, z, i);
            }
            return w;
        }

        public byte[] HintBitPack(IList<BitArray> h)
        {
            int yLength = _parameters.AMatrixDimensions.K + _parameters.Omega;
            byte[] y = new byte[yLength];
            Array.Fill(y, (byte)0);

            byte index = 0;

            for (int i = 0; i < h.Count(); i++)
            {
                for (byte j = 0; j <= byte.MaxValue; j++)
                {
                    if(h[i][j] == false)
                    {
                        continue;
                    }
                    
                    y[index] = j;
                    index++;
                }
                y[_parameters.Omega + i] = index;
            }

            return y;
        }

        public IList<BitArray>? HintBitUnpack(byte[] y)
        {
            BitArray[] h = new BitArray[_parameters.AMatrixDimensions.K];
            
            for(byte i = 0; i < h.Count(); i++)
            {
                h[i] = new BitArray(256);
            }

            byte index = 0;

            for (int i = 0; i < h.Count(); i++)
            {
                if(y[_parameters.Omega + i] < index)
                {
                    return null;
                }

                if(y[_parameters.Omega + i] > _parameters.Omega)
                {
                    return null;
                }

                byte first = index;

                while(index < y[_parameters.Omega + i])
                {
                    if (y[index] >= first)
                    {
                        return null;
                    }

                    h[i][y[index]] = true;

                    index++;
                }
            }

            for(byte i = index; i < _parameters.Omega; i++)
            {
                if (y[i] != 0)
                {
                    return null;
                }
            }

            return h;
        }

        private int UnpackCoefficient(short c, BitArray z, int i)
        {
            BitArray bits = new BitArray(c);

            for (int j = 0; j < c; j++)
            {
                bits[j] = z[i * c + j];
            }

            return BitsToInteger(bits, c);
        }
    }
}
