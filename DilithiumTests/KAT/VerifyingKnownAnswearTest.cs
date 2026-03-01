using System.Collections;
using System.Text.Json;
using Core.Helpers;
using CrystalsDilithium;
using CrystalsDilithium.Algorithms;
using CrystalsDilithium.Algorithms.Operations;
using DilithiumTests.KAT.Models.Verifying;

namespace DilithiumTests.KAT
{
    public class VerifyingKnownAnswearTest
    {
        private static readonly string DataPath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "KAT",
            "Data",
            "Veryfing",
            "internalProjection.json"
        );

        public static IEnumerable<object[]> VerifyingTestData()
        {
            string json = File.ReadAllText(DataPath);
            InternalProjection data = JsonSerializer.Deserialize<InternalProjection>(json)!;

            foreach (TestGroup group in data.TestGroups)
            {
                if (group.PreHash != "pure")
                {
                    continue;
                }

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

                    byte[] ctx = string.IsNullOrWhiteSpace(test.Context)
                        ? []
                        : Convert.FromHexString(test.Context);

                    yield return
                    [
                        test.TcId,
                        Convert.FromHexString(test.Pk),
                        ctx,
                        Convert.FromHexString(test.Message),
                        Convert.FromHexString(test.Signature),
                        test.TestPassed,
                        parameters,
                    ];
                }
            }
        }

        [Theory]
        [MemberData(nameof(VerifyingTestData))]
        public void Verifying_ShouldReturnExpectedResult(
            int tcId,
            byte[] pk,
            byte[] ctx,
            byte[] message,
            byte[] signature,
            bool expectedResult,
            DilithiumParameters parameters
        )
        {
            Verifier verifier = new(parameters);
            BitAlgorithms bitAlgorithms = new(parameters);

            byte[] messagePrefix = ByteArrayHelpers.ConcatBytes(
                bitAlgorithms.IntegerToBytes(0, 1),
                bitAlgorithms.IntegerToBytes(ctx.Length, 1),
                ctx
            );

            BitArray messagePrim = BitArrayHelpers.Concat(
                bitAlgorithms.BytesToBits(messagePrefix),
                bitAlgorithms.BytesToBits(message)
            );

            bool result = verifier.VerifyInternal(pk, messagePrim, signature);

            Assert.Equal(expectedResult, result);
        }
    }
}
