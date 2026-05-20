using System.Security.Cryptography;
using System.Text.Json;
using Core.Helpers;
using SphincsPlus;
using SphincsPlus.Algorithms;
using SphincsPlus.Algorithms.Operations;
using SphincsPlus.Models;
using SphincsPlusTests.KAT.Models.Veryfing;

namespace SphincsPlusTests.KAT
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

                    if (!IsSupportedHashAlg(group.PreHash, test.HashAlg))
                    {
                        continue;
                    }

                    yield return
                    [
                        test.TcId,
                        Convert.FromHexString(test.Pk),
                        Convert.FromHexString(test.Message),
                        string.IsNullOrEmpty(test.Context) ? [] : Convert.FromHexString(test.Context),
                        group.PreHash,
                        test.HashAlg ?? "none",
                        group.SignatureInterface,
                        Convert.FromHexString(test.Signature),
                        test.TestPassed ?? false,
                        parameters,
                    ];
                }
            }
        }

        [Theory]
        [MemberData(nameof(VerifyingTestData))]
        public void Verifying_ShouldReturnExpectedResult(
            int? tcId,
            byte[] pk,
            byte[] message,
            byte[] ctx,
            string preHash,
            string hashAlg,
            string signatureInterface,
            byte[] signature,
            bool expectedResult,
            SphincsPlusParameters parameters
        )
        {
            Verifier verifier = new(parameters);
            PublicKey publicKey = PublicKey.FromBytesArray(pk);

            byte[] mPrime = BuildMessage(message, ctx, preHash, hashAlg, signatureInterface);

            bool res = verifier.VerifyInternal(mPrime, signature, publicKey);

            Assert.Equal(expectedResult, res);
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
                    ByteConversions.ToByte(0, 1),
                    ByteConversions.ToByte(ctx.Length, 1),
                    ctx,
                    message
                );
            }

            (byte[] oid, byte[] hashedMessage) = PreHashMessage(message, hashAlg);

            return ByteArrayHelpers.ConcatBytes(
                ByteConversions.ToByte(1, 1),
                ByteConversions.ToByte(ctx.Length, 1),
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
