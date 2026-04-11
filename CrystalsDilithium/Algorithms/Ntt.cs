using Core.Helpers;

namespace CrystalsDilithium.Algorithms
{
    internal static class Ntt
    {
        private static readonly int[] Zetas =
        {
            0,
            4808194,
            3765607,
            3761513,
            5178923,
            5496691,
            5234739,
            5178987,
            7778734,
            3542485,
            2682288,
            2129892,
            3764867,
            7375178,
            557458,
            7159240,
            5010068,
            4317364,
            2663378,
            6705802,
            4855975,
            7946292,
            676590,
            7044481,
            5152541,
            1714295,
            2453983,
            1460718,
            7737789,
            4795319,
            2815639,
            2283733,
            3602218,
            3182878,
            2740543,
            4793971,
            5269599,
            2101410,
            3704823,
            1159875,
            394148,
            928749,
            1095468,
            4874037,
            2071829,
            4361428,
            3241972,
            2156050,
            3415069,
            1759347,
            7562881,
            4805951,
            3756790,
            6444618,
            6663429,
            4430364,
            5483103,
            3192354,
            556856,
            3870317,
            2917338,
            1853806,
            3345963,
            1858416,
            3073009,
            1277625,
            5744944,
            3852015,
            4183372,
            5157610,
            5258977,
            8106357,
            2508980,
            2028118,
            1937570,
            4564692,
            2811291,
            5396636,
            7270901,
            4158088,
            1528066,
            482649,
            1148858,
            5418153,
            7814814,
            169688,
            2462444,
            5046034,
            4213992,
            4892034,
            1987814,
            5183169,
            1736313,
            235407,
            5130263,
            3258457,
            5801164,
            1787943,
            5989328,
            6125690,
            3482206,
            4197502,
            7080401,
            6018354,
            7062739,
            2461387,
            3035980,
            621164,
            3901472,
            7153756,
            2925816,
            3374250,
            1356448,
            5604662,
            2683270,
            5601629,
            4912752,
            2312838,
            7727142,
            7921254,
            348812,
            8052569,
            1011223,
            6026202,
            4561790,
            6458164,
            6143691,
            1744507,
            1753,
            6444997,
            5720892,
            6924527,
            2660408,
            6600190,
            8321269,
            2772600,
            1182243,
            87208,
            636927,
            4415111,
            4423672,
            6084020,
            5095502,
            4663471,
            8352605,
            822541,
            1009365,
            5926272,
            6400920,
            1596822,
            4423473,
            4620952,
            6695264,
            4969849,
            2678278,
            4611469,
            4829411,
            635956,
            8129971,
            5925040,
            4234153,
            6607829,
            2192938,
            6653329,
            2387513,
            4768667,
            8111961,
            5199961,
            3747250,
            2296099,
            1239911,
            4541938,
            3195676,
            2642980,
            1254190,
            8368000,
            2998219,
            141835,
            8291116,
            2513018,
            7025525,
            613238,
            7070156,
            6161950,
            7921677,
            6458423,
            4040196,
            4908348,
            2039144,
            6500539,
            7561656,
            6201452,
            6757063,
            2105286,
            6006015,
            6346610,
            586241,
            7200804,
            527981,
            5637006,
            6903432,
            1994046,
            2491325,
            6987258,
            507927,
            7192532,
            7655613,
            6545891,
            5346675,
            8041997,
            2647994,
            3009748,
            5767564,
            4148469,
            749577,
            4357667,
            3980599,
            2569011,
            6764887,
            1723229,
            1665318,
            2028038,
            1163598,
            5011144,
            3994671,
            8368538,
            7009900,
            3020393,
            3363542,
            214880,
            545376,
            7609976,
            3105558,
            7277073,
            508145,
            7826699,
            860144,
            3430436,
            140244,
            6866265,
            6195333,
            3123762,
            2358373,
            6187330,
            5365997,
            6663603,
            2926054,
            7987710,
            8077412,
            3531229,
            4405932,
            4606686,
            1900052,
            7598542,
            1054478,
            7648983,
        };

        private const int F = 8347681;

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
                        int t = Modulo.FloorMod((long)z * wHat[j + len], DilithiumParameters.Q);
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
        /// then multiplies each coefficient by f = 256⁻¹ mod q (= <c>8347681</c>) to normalise.
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
                        w[j + len] = Modulo.FloorMod((long)z * w[j + len], DilithiumParameters.Q);
                    }

                    start += 2 * len;
                }
                len = 2 * len;
            }

            for (int j = 0; j < 256; j++)
            {
                w[j] = Modulo.FloorMod((long)w[j] * F, DilithiumParameters.Q);
            }

            return w;
        }
    }
}
