using System.Collections;
using System.Security.Cryptography;
using System.Text.Json;
using Core.Helpers;
using CrystalsDilithium;
using CrystalsDilithium.Algorithms;
using CrystalsDilithium.Algorithms.Operations;
using DilithiumTests.KAT.Models.Verifying;

namespace DilithiumTests.KAT
{
    public class VerifyingKnownAnswerTest
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
                DilithiumParameters parameters = group.ParameterSet switch
                {
                    "ML-DSA-44" => DilithiumParametersProvider.SecurityLevel2Parameters,
                    "ML-DSA-65" => DilithiumParametersProvider.SecurityLevel3Parameters,
                    "ML-DSA-87" => DilithiumParametersProvider.SecurityLevel5Parameters,
                    _ => throw new InvalidOperationException(
                        $"Unknown parameter set: {group.ParameterSet}"
                    ),
                };

                if (group.ExternalMu)
                {
                    continue;
                }

                foreach (Test test in group.Tests)
                {
                    if (test.Deferred)
                    {
                        continue;
                    }

                    if (!IsSupportedHashAlg(group.PreHash, test.HashAlg))
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
                        group.PreHash,
                        test.HashAlg ?? "none",
                        group.SignatureInterface,
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
            string preHash,
            string hashAlg,
            string signatureInterface,
            byte[] signature,
            bool expectedResult,
            DilithiumParameters parameters
        )
        {
            Verifier verifier = new(parameters);
            BitAlgorithms bitAlgorithms = new(parameters);

            byte[] mPrimeBytes = BuildMessage(message, ctx, preHash, hashAlg, signatureInterface);
            BitArray mPrim = bitAlgorithms.BytesToBits(mPrimeBytes);

            bool result = verifier.VerifyInternal(pk, mPrim, signature);

            Assert.Equal(expectedResult, result);
        }

        private static byte[] BuildMessage(
            byte[] message,
            byte[] ctx,
            string preHash,
            string hashAlg,
            string signatureInterface
        )
        {
            if (signatureInterface == "internal")
            {
                return message;
            }

            if (preHash == "pure")
            {
                return ByteArrayHelpers.ConcatBytes(
                    [0x00],
                    [(byte)ctx.Length],
                    ctx,
                    message
                );
            }

            (byte[] oid, byte[] hashedMessage) = PreHashMessage(message, hashAlg);

            return ByteArrayHelpers.ConcatBytes(
                [0x01],
                [(byte)ctx.Length],
                ctx,
                oid,
                hashedMessage
            );
        }

        private static bool IsSupportedHashAlg(string preHash, string? hashAlg)
        {
            if (preHash != "preHash")
            {
                return true;
            }

            return hashAlg switch
            {
                "SHA2-256" or "SHA2-512" or "SHAKE-128" or "SHAKE-256" => true,
                _ => false,
            };
        }

        private static (byte[] oid, byte[] hashedMessage) PreHashMessage(byte[] message, string hashAlg)
        {
            return hashAlg switch
            {
                "SHA2-256" => (Oid(0x01), SHA256.HashData(message)),
                "SHA2-512" => (Oid(0x03), SHA512.HashData(message)),
                "SHAKE-128" => (Oid(0x0B), Shake128.HashData(message, 32)),
                "SHAKE-256" => (Oid(0x0C), Shake256.HashData(message, 64)),
                _ => throw new InvalidOperationException($"Unsupported hash algorithm: {hashAlg}"),
            };
        }

        private static byte[] Oid(byte lastByte) =>
            [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, lastByte];
    }
}
