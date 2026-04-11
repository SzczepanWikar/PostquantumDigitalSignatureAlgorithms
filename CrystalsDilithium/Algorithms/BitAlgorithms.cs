using System.Collections;
using System.Diagnostics;
using Core.Helpers;

namespace CrystalsDilithium.Algorithms
{
    internal sealed class BitAlgorithms
    {
        private readonly DilithiumParameters _parameters;

        public BitAlgorithms(DilithiumParameters parameters)
        {
            _parameters = parameters;
        }

        /// <summary>
        /// Algorithm 3 — IntegerToBits. Converts a non-negative integer <paramref name="x"/>
        /// to a bit array of length <paramref name="alpha"/> using little-endian ordering.
        /// </summary>
        public BitArray IntegerToBits(int x, int alpha)
        {
            Debug.Assert(x >= 0, "Input must be non-negative.");
            Debug.Assert(alpha > 0, "Bit length must be positive.");

            int xPrim = x;
            BitArray y = new BitArray(alpha);

            for (int i = 0; i < alpha; i++)
            {
                y[i] = xPrim % 2 == 1;
                xPrim = xPrim / 2;
            }

            return y;
        }

        /// <summary>
        /// Algorithm 4 — BitsToInteger. Converts a bit array <paramref name="y"/> of length
        /// <paramref name="alpha"/> (little-endian) to a non-negative integer.
        /// </summary>
        public int BitsToInteger(BitArray y, int alpha)
        {
            Debug.Assert(y.Length > 0, "Bit array must not be empty.");
            Debug.Assert(alpha > 0, "Bit length must be positive.");
            Debug.Assert(
                y.Length >= alpha,
                "Bit array length must be at least as long as the specified bit length."
            );

            int result = 0;

            for (int i = 1; i <= alpha; i++)
            {
                result = 2 * result + y[alpha - i].ToInt32();
            }

            return result;
        }

        /// <summary>
        /// Algorithm 5 — IntegerToBytes. Converts a non-negative integer <paramref name="x"/>
        /// to a byte array of length <paramref name="alpha"/> using little-endian ordering.
        /// </summary>
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

        /// <summary>
        /// Algorithm 6 — BitsToBytes. Packs a bit array <paramref name="y"/> into a byte array,
        /// grouping bits in little-endian order within each byte.
        /// </summary>
        public byte[] BitsToBytes(BitArray y)
        {
            Debug.Assert(y.Length > 0, "Bit array must not be empty.");

            int byteCount = (y.Length + 7) / 8;
            byte[] bytes = new byte[byteCount];
            Array.Fill(bytes, (byte)0);

            for (int i = 0; i < y.Length; i++)
            {
                bytes[i / 8] = (byte)(bytes[i / 8] + y[i].ToByte() * (1 << (i % 8)));
            }

            return bytes;
        }

        /// <summary>
        /// Algorithm 7 — BytesToBits. Unpacks a byte array <paramref name="z"/> into a bit array,
        /// expanding each byte in little-endian order.
        /// </summary>
        public BitArray BytesToBits(byte[] z) => new BitArray(z);

        /// <summary>
        /// Algorithm 8 — CoeffFromThreeBytes. Generates a uniform coefficient in Z_q
        /// from three bytes by rejection sampling. Returns <see langword="null"/> when
        /// the candidate ≥ q.
        /// </summary>
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

        /// <summary>
        /// Algorithm 9 — CoeffFromHalfByte. Generates a uniform coefficient in S_η
        /// from a 4-bit input by rejection sampling. Returns <see langword="null"/> when
        /// the candidate falls outside the valid range for the current η.
        /// </summary>
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

        /// <summary>
        /// Algorithm 10 — SimpleBitPack. Encodes a degree-255 polynomial <paramref name="w"/>
        /// with coefficients in [0, 2^<paramref name="b"/>) into a byte array.
        /// Each coefficient is stored as a <paramref name="b"/>-bit little-endian value.
        /// </summary>
        public byte[] SimpleBitPack(int[] w, int b)
        {
            Debug.Assert(w.Length > 0, "Input array must not be empty.");
            Debug.Assert(b > 0, "b must be positive.");

            byte bitLength = b.GetBitLength();

            BitArray bits = new(0);

            for (int i = 0; i < 256; i++)
            {
                bits = BitArrayHelpers.Concat(bits, IntegerToBits(w[i], bitLength));
            }

            byte[] res = BitsToBytes(bits);

            return res;
        }

        /// <summary>
        /// Algorithm 11 — BitPack. Encodes a degree-255 polynomial <paramref name="w"/>
        /// with coefficients in [-<paramref name="a"/>, <paramref name="b"/>] into a byte array.
        /// Each coefficient is stored as (<paramref name="b"/> − w[i]) in
        /// ⌈log₂(<paramref name="a"/> + <paramref name="b"/>)⌉ bits.
        /// </summary>
        public byte[] BitPack(int[] w, int a, int b)
        {
            Debug.Assert(w.Length > 0, "Input array must not be empty.");

            byte bitLength = (a + b).GetBitLength();
            BitArray bits = new(0);

            for (int i = 0; i < 256; i++)
            {
                bits = BitArrayHelpers.Concat(bits, IntegerToBits(b - w[i], bitLength));
            }

            byte[] res = BitsToBytes(bits);
            return res;
        }

        /// <summary>
        /// Algorithm 12 — SimpleBitUnpack. Decodes a byte array <paramref name="v"/> into
        /// a degree-255 polynomial with coefficients in [0, 2^<paramref name="b"/>).
        /// Inverse of <see cref="SimpleBitPack"/>.
        /// </summary>
        public int[] SimpleBitUnpack(byte[] v, int b)
        {
            short c = b.GetBitLength();
            BitArray z = BytesToBits(v);

            int[] w = new int[256];

            for (int i = 0; i < 256; i++)
            {
                w[i] = UnpackCoefficient(c, z, i);
            }

            return w;
        }

        /// <summary>
        /// Algorithm 13 — BitUnpack. Decodes a byte array <paramref name="v"/> into
        /// a degree-255 polynomial with coefficients in [-<paramref name="a"/>, <paramref name="b"/>].
        /// Inverse of <see cref="BitPack"/>.
        /// </summary>
        public int[] BitUnpack(byte[] v, int a, int b)
        {
            short c = (a + b).GetBitLength();
            BitArray z = BytesToBits(v);

            int[] w = new int[256];

            for (int i = 0; i < 256; i++)
            {
                w[i] = b - UnpackCoefficient(c, z, i);
            }
            return w;
        }

        /// <summary>
        /// Algorithm 14 — HintBitPack. Encodes the hint vector <paramref name="h"/> (k polynomials
        /// over {0,1}) into a byte array of length ω + k. Non-zero positions within each polynomial
        /// are listed in ascending order, followed by an end-of-polynomial index sentinel.
        /// </summary>
        public byte[] HintBitPack(IList<BitArray> h)
        {
            int yLength = _parameters.AMatrixDimensions.K + _parameters.Omega;
            byte[] y = new byte[yLength];

            int index = 0;

            for (int i = 0; i < h.Count(); i++)
            {
                for (int j = 0; j <= 255; j++)
                {
                    if (h[i][j] == false)
                    {
                        continue;
                    }

                    y[index] = (byte)j;
                    index++;
                }
                y[_parameters.Omega + i] = (byte)index;
            }

            return y;
        }

        /// <summary>
        /// Algorithm 15 — HintBitUnpack. Decodes a byte array <paramref name="y"/> of length ω + k
        /// into the hint vector (k polynomials over {0,1}). Returns <see langword="null"/> if the
        /// encoding is malformed (out-of-order indices, exceeded ω budget, or non-zero padding).
        /// Inverse of <see cref="HintBitPack"/>.
        /// </summary>
        public BitArray[]? HintBitUnpack(byte[] y)
        {
            BitArray[] h = new BitArray[_parameters.AMatrixDimensions.K];

            for (byte i = 0; i < h.Count(); i++)
            {
                h[i] = new BitArray(256);
            }

            byte index = 0;

            for (int i = 0; i < h.Count(); i++)
            {
                if (y[_parameters.Omega + i] < index)
                {
                    return null;
                }

                if (y[_parameters.Omega + i] > _parameters.Omega)
                {
                    return null;
                }

                byte first = index;

                while (index < y[_parameters.Omega + i])
                {
                    if (index > first && y[index - 1] >= y[index])
                    {
                        return null;
                    }

                    h[i][y[index]] = true;

                    index++;
                }
            }

            for (byte i = index; i < _parameters.Omega; i++)
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
