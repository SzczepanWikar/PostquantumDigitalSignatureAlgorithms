using System.Collections;
using System.Text.Json;
using Core.Helpers;
using CrystalsDilithium;
using CrystalsDilithium.Algorithms;
using CrystalsDilithium.Algorithms.Operations;
using DilithiumTests.KAT.Models.Signing;

namespace DilithiumTests.KAT
{
    public class SigningKnownAnswearTest
    {
        private static readonly string DataPath = Path.Combine(
            AppDomain.CurrentDomain.BaseDirectory,
            "KAT",
            "Data",
            "Signing",
            "internalProjection.json"
        );

        public static IEnumerable<object[]> SigningTestData()
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

                    byte[] rnd = string.IsNullOrEmpty(test.Rnd)
                        ? new byte[32]
                        : Convert.FromHexString(test.Rnd);

                    yield return
                    [
                        test.TcId,
                        Convert.FromHexString(test.Sk),
                        rnd,
                        ctx,
                        Convert.FromHexString(test.Message),
                        Convert.FromHexString(test.Signature),
                        parameters,
                    ];
                }
            }
        }

        [Theory]
        [MemberData(nameof(SigningTestData))]
        public void Signing_ShouldGenerateExpectedSignature(
            int tcId,
            byte[] sk,
            byte[] rnd,
            byte[] ctx,
            byte[] message,
            byte[] expectedSignature,
            DilithiumParameters parameters
        )
        {
            Signer signer = new(parameters);
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

            byte[] sigma = signer.SignInternal(sk, messagePrim, rnd);

            Assert.Equal(expectedSignature, sigma);
        }
    }
}
