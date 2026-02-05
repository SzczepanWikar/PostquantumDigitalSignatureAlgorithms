using System.Collections;
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
    }
}
