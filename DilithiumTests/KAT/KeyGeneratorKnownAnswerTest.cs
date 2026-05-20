using System.Text.Json;
using CrystalsDilithium;
using DilithiumTests.KAT.Models.KeyGeneration;

namespace DilithiumTests.KAT
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
                DilithiumParameters parameters = group.ParameterSet switch
                {
                    "ML-DSA-44" => DilithiumParametersProvider.SecurityLevel2Parameters,
                    "ML-DSA-65" => DilithiumParametersProvider.SecurityLevel3Parameters,
                    "ML-DSA-87" => DilithiumParametersProvider.SecurityLevel5Parameters,
                    _ => throw new InvalidOperationException(
                        $"Unknown parameter set: {group.ParameterSet}"
                    ),
                };

                foreach (Test test in group.Tests)
                {
                    if (test.Deferred)
                    {
                        continue;
                    }

                    yield return
                    [
                        test.TcId,
                        Convert.FromHexString(test.Seed),
                        Convert.FromHexString(test.Pk),
                        Convert.FromHexString(test.Sk),
                        parameters,
                    ];
                }
            }
        }

        [Theory]
        [MemberData(nameof(KeyGenTestData))]
        public void KeyGen_WithKnownSeed_ProducesExpectedKeyPair(
            int tcId,
            byte[] seed,
            byte[] expectedPk,
            byte[] expectedSk,
            DilithiumParameters parameters
        )
        {
            CrystalsDilithiumAlgorithm algorithm = new CrystalsDilithiumAlgorithm(parameters);

            var (pk, sk) = algorithm.KeyGen(seed);

            Assert.Equal(expectedPk, pk);
            Assert.Equal(expectedSk, sk);
        }
    }
}
