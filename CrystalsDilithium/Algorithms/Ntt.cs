using Core.Helpers;

namespace CrystalsDilithium.Algorithms
{
    internal static class Ntt
    {
        // Powers of ζ in the Montgomery domain: each entry is ζ^{BitRev₈(i)} · 2³² mod q,
        // reduced to [0, q). Used together with MontgomeryReduce in the butterfly steps.
        private static readonly int[] Zetas =
        {
            0,
            25847,
            5771523,
            7861508,
            237124,
            7602457,
            7504169,
            466468,
            1826347,
            2353451,
            8021166,
            6288512,
            3119733,
            5495562,
            3111497,
            2680103,
            2725464,
            1024112,
            7300517,
            3585928,
            7830929,
            7260833,
            2619752,
            6271868,
            6262231,
            4520680,
            6980856,
            5102745,
            1757237,
            8360995,
            4010497,
            280005,
            2706023,
            95776,
            3077325,
            3530437,
            6718724,
            4788269,
            5842901,
            3915439,
            4519302,
            5336701,
            3574422,
            5512770,
            3539968,
            8079950,
            2348700,
            7841118,
            6681150,
            6736599,
            3505694,
            4558682,
            3507263,
            6239768,
            6779997,
            3699596,
            811944,
            531354,
            954230,
            3881043,
            3900724,
            5823537,
            2071892,
            5582638,
            4450022,
            6851714,
            4702672,
            5339162,
            6927966,
            3475950,
            2176455,
            6795196,
            7122806,
            1939314,
            4296819,
            7380215,
            5190273,
            5223087,
            4747489,
            126922,
            3412210,
            7396998,
            2147896,
            2715295,
            5412772,
            4686924,
            7969390,
            5903370,
            7709315,
            7151892,
            8357436,
            7072248,
            7998430,
            1349076,
            1852771,
            6949987,
            5037034,
            264944,
            508951,
            3097992,
            44288,
            7280319,
            904516,
            3958618,
            4656075,
            8371839,
            1653064,
            5130689,
            2389356,
            8169440,
            759969,
            7063561,
            189548,
            4827145,
            3159746,
            6529015,
            5971092,
            8202977,
            1315589,
            1341330,
            1285669,
            6795489,
            7567685,
            6940675,
            5361315,
            4499357,
            4751448,
            3839961,
            2091667,
            3407706,
            2316500,
            3817976,
            5037939,
            2244091,
            5933984,
            4817955,
            266997,
            2434439,
            7144689,
            3513181,
            4860065,
            4621053,
            7183191,
            5187039,
            900702,
            1859098,
            909542,
            819034,
            495491,
            6767243,
            8337157,
            7857917,
            7725090,
            5257975,
            2031748,
            3207046,
            4823422,
            7855319,
            7611795,
            4784579,
            342297,
            286988,
            5942594,
            4108315,
            3437287,
            5038140,
            1735879,
            203044,
            2842341,
            2691481,
            5790267,
            1265009,
            4055324,
            1247620,
            2486353,
            1595974,
            4613401,
            1250494,
            2635921,
            4832145,
            5386378,
            1869119,
            1903435,
            7329447,
            7047359,
            1237275,
            5062207,
            6950192,
            7929317,
            1312455,
            3306115,
            6417775,
            7100756,
            1917081,
            5834105,
            7005614,
            1500165,
            777191,
            2235880,
            3406031,
            7838005,
            5548557,
            6709241,
            6533464,
            5796124,
            4656147,
            594136,
            4603424,
            6366809,
            2432395,
            2454455,
            8215696,
            1957272,
            3369112,
            185531,
            7173032,
            5196991,
            162844,
            1616392,
            3014001,
            810149,
            1652634,
            4686184,
            6581310,
            5341501,
            3523897,
            3866901,
            269760,
            2213111,
            7404533,
            1717735,
            472078,
            7953734,
            1723600,
            6577327,
            1910376,
            6712985,
            7276084,
            8119771,
            4546524,
            5441381,
            6144432,
            7959518,
            6094090,
            183443,
            7403526,
            1612842,
            4834730,
            7826001,
            3919660,
            8332111,
            7018208,
            3937738,
            1400424,
            7534263,
            1976782,
        };

        // f = 256⁻¹ · 2³² mod q. The trailing 2³² factor is removed by the final MontgomeryReduce,
        // leaving the standard-domain scaling 256⁻¹ mod q.
        private const int F = 16382;

        // q⁻¹ mod 2³², used by Montgomery reduction.
        private const int QINV = 58728449;

        /// <summary>
        /// Algorithm 41 — NTT (polynomial vector variant). Applies <see cref="ForwardNtt(int[])"/>
        /// to each polynomial in <paramref name="w"/> and returns the result vector in NTT domain.
        /// </summary>
        public static int[][] ForwardNtt(int[][] w)
        {
            int[][] res = new int[w.Length][];

            for (int i = 0; i < w.Length; i++)
            {
                res[i] = ForwardNtt(w[i]);
            }

            return res;
        }

        /// <summary>
        /// Algorithm 42 — NTT⁻¹ (polynomial vector variant). Applies <see cref="InverseNtt(int[])"/>
        /// to each polynomial in <paramref name="wHat"/> and returns the result vector in standard domain.
        /// </summary>
        public static int[][] InverseNtt(int[][] wHat)
        {
            int[][] res = new int[wHat.Length][];

            for (int i = 0; i < wHat.Length; i++)
            {
                res[i] = InverseNtt(wHat[i]);
            }

            return res;
        }

        /// <summary>
        /// Algorithm 41 — NTT. Computes the forward Number Theoretic Transform of polynomial
        /// <paramref name="w"/> ∈ R_q using the precomputed zeta table. Iterates from the largest
        /// half-length (128) down to 1 in a Cooley-Tukey butterfly structure, consuming zetas
        /// ζ^{BitRev₈(1)}, …, ζ^{BitRev₈(255)} in order. Result is the NTT representation ŵ ∈ R_q.
        /// </summary>
        public static int[] ForwardNtt(int[] w)
        {
            int[] wHat = new int[w.Length];
            Array.Copy(w, wHat, w.Length);

            byte m = 0;
            int start,
                len = 128;

            while (len >= 1)
            {
                start = 0;

                while (start < 256)
                {
                    m++;
                    int z = Zetas[m];

                    for (int j = start; j < start + len; j++)
                    {
                        int t = MontgomeryReduce((long)z * wHat[j + len]);
                        int sub = wHat[j] - t;
                        wHat[j + len] = sub < 0 ? sub + DilithiumParameters.Q : sub;
                        int add = wHat[j] + t;
                        wHat[j] = add >= DilithiumParameters.Q ? add - DilithiumParameters.Q : add;
                    }
                    start += 2 * len;
                }
                len = len / 2;
            }

            return wHat;
        }

        /// <summary>
        /// Algorithm 42 — NTT⁻¹. Computes the inverse Number Theoretic Transform of
        /// <paramref name="wHat"/> ∈ R_q using the precomputed zeta table traversed in reverse.
        /// Uses a Gentleman-Sande butterfly structure iterating from half-length 1 up to 128,
        /// then multiplies each coefficient by f (Montgomery-domain 256⁻¹) and reduces, normalising
        /// by 256⁻¹ mod q.
        /// Inverse of <see cref="ForwardNtt(int[])"/>.
        /// </summary>
        public static int[] InverseNtt(int[] wHat)
        {
            int[] w = new int[wHat.Length];
            Array.Copy(wHat, w, wHat.Length);

            short m = 256;
            int start,
                len = 1;

            while (len < 256)
            {
                start = 0;
                while (start < 256)
                {
                    m--;
                    int z = -Zetas[m];

                    for (int j = start; j < start + len; j++)
                    {
                        int t = w[j];
                        int add = t + w[j + len];
                        w[j] = add >= DilithiumParameters.Q ? add - DilithiumParameters.Q : add;
                        int sub = t - w[j + len];
                        w[j + len] = sub < 0 ? sub + DilithiumParameters.Q : sub;
                        w[j + len] = MontgomeryReduce((long)z * w[j + len]);
                    }

                    start += 2 * len;
                }
                len = 2 * len;
            }

            for (int j = 0; j < 256; j++)
            {
                w[j] = MontgomeryReduce((long)w[j] * F);
            }

            return w;
        }

        /// <summary>
        /// Montgomery reduction. Given <paramref name="a"/> = x · 2³², returns x mod q in the
        /// range [0, q). Operands must be in the Montgomery domain (the <see cref="Zetas"/> table
        /// stores ζ · 2³² mod q); the reduction removes the extra 2³² factor.
        /// </summary>
        private static int MontgomeryReduce(long a)
        {
            int t = (int)((a % (1L << 32)) * QINV);
            int res = (int)((a - (long)t * DilithiumParameters.Q) >> 32);
            return res < 0 ? res + DilithiumParameters.Q : res;
        }
    }
}
