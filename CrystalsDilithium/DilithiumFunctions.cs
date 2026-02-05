using System.Collections;
using System.Diagnostics;
using System.Runtime.Intrinsics.Arm;
using System.Security.Cryptography;

namespace CrystalsDilithium
{
    public sealed class DilithiumFunctions
    {
        private readonly DilithiumParameters _parameters;

        public DilithiumFunctions(DilithiumParameters parameters)
        {
            _parameters = parameters;
        }
        
        public short[] SampleInBall(byte[] seed) 
        {
            short[] c = new short[256];
            Array.Fill(c, (short)0);

            using Shake256 shake256 = new();
            shake256.AppendData(seed);

            byte[] hash = shake256.Read(8);
            BitArray h = new BitArray(hash);

            for (int i = 256 - _parameters.Tau; i < 256; i++)
            {
                int j = shake256.Read(1)[0];
                
                while (j > i)
                {
                    j = shake256.Read(1)[0];
                }

                c[i] = c[j];
                c[j] = (short)Math.Pow(-1, h[i + _parameters.Tau - 256] ? 1 : 0);
            }

            return c;
        }
        
        public (int r1, int r0) Power2Round(int r)
        {
            Debug.Assert(r >= 0, "Input must be non-negative.");
            r = r % _parameters.Q;

            int TwoToPowerOfD = 1 << _parameters.D;

            int r0 = ModPlusMinus(r, TwoToPowerOfD);
            int r1 = (r - r0) / TwoToPowerOfD;

            return (r1, r0);
        }

        public static int ModPlusMinus(int n, int m)
        {
            if ((m & (m - 1)) != 0)
            {
                throw new ArgumentException("Modulo must be a power of 2.", nameof(m));
            }

            int mod = n & (m - 1); 
            if (mod > (m >> 1))    
            {
                mod -= m;
            }

            return mod;
        }
    }
}
