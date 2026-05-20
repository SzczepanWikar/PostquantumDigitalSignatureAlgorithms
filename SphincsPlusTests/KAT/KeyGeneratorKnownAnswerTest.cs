using System.Text.Json;
using SphincsPlus;
using SphincsPlus.Algorithms.Operations;
using SphincsPlusTests.KAT.Models.KeyGeneration;

namespace SphincsPlusTests.KAT
{
    public class KeyGeneratorKnownAnswerTest
    {
        private static readonly string DataPath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "KAT",
            "Data",
            "KeyGeneration",
            "internalProjection.json"
        );

        public static IEnumerable<object[]> KeyGenTestData()
        {
            string json = File.ReadAllText(DataPath);
            InternalProjection data = JsonSerializer.Deserialize<InternalProjection>(json)!;

            foreach (TestGroup group in data.TestGroups)
            {
                SphincsPlusParameters parameters = group.ParameterSet switch
                {
                    "SLH-DSA-SHA2-128s" => SphincsPlusParametersProvider.Sha2_128s,
                    "SLH-DSA-SHA2-128f" => SphincsPlusParametersProvider.Sha2_128f,
                    "SLH-DSA-SHAKE-128s" => SphincsPlusParametersProvider.Shake_128s,
                    "SLH-DSA-SHAKE-128f" => SphincsPlusParametersProvider.Shake_128f,
                    "SLH-DSA-SHA2-192s" => SphincsPlusParametersProvider.Sha2_192s,
                    "SLH-DSA-SHA2-192f" => SphincsPlusParametersProvider.Sha2_192f,
                    "SLH-DSA-SHAKE-192s" => SphincsPlusParametersProvider.Shake_192s,
                    "SLH-DSA-SHAKE-192f" => SphincsPlusParametersProvider.Shake_192f,
                    "SLH-DSA-SHA2-256s" => SphincsPlusParametersProvider.Sha2_256s,
                    "SLH-DSA-SHA2-256f" => SphincsPlusParametersProvider.Sha2_256f,
                    "SLH-DSA-SHAKE-256s" => SphincsPlusParametersProvider.Shake_256s,
                    "SLH-DSA-SHAKE-256f" => SphincsPlusParametersProvider.Shake_256f,
                    _ => throw new InvalidOperationException(
                        $"Unknown parameter set: {group.ParameterSet}"
                    ),
                };

                foreach (Test test in group.Tests)
                {
                    if (test.Deferred == true)
                    {
                        continue;
                    }

                    yield return
                    [
                        test.TcId,
                        Convert.FromHexString(test.SkSeed),
                        Convert.FromHexString(test.SkPrf),
                        Convert.FromHexString(test.PkSeed),
                        Convert.FromHexString(test.Pk),
                        Convert.FromHexString(test.Sk),
                        parameters,
                    ];
                }
            }
        }

        [Theory]
        [MemberData(nameof(KeyGenTestData))]
        public void KeyGen_WithKnownSeeds_ProducesExpectedKeyPair(
            int? tcId,
            byte[] skSeed,
            byte[] skPrf,
            byte[] pkSeed,
            byte[] expectedPk,
            byte[] expectedSk,
            SphincsPlusParameters parameters
        )
        {
            KeyGenerator keyGenerator = new(parameters);

            var (sk, pk) = keyGenerator.KeyGenInternal(skSeed, skPrf, pkSeed);

            Assert.Equal(expectedPk, pk.ToBytesArray());
            Assert.Equal(expectedSk, sk.ToBytesArray());
        }
    }
}
