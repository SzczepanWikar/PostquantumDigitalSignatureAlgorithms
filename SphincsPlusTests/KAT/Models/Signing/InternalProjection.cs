using System.Text.Json.Serialization;

namespace SphincsPlusTests.KAT.Models.Signing
{
    public class InternalProjection
    {
        [JsonPropertyName("vsId")]
        public int? VsId { get; set; }

        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; }

        [JsonPropertyName("mode")]
        public string Mode { get; set; }

        [JsonPropertyName("revision")]
        public string Revision { get; set; }

        [JsonPropertyName("isSample")]
        public bool? IsSample { get; set; }

        [JsonPropertyName("testGroups")]
        public List<TestGroup> TestGroups { get; set; }
    }

    public class Test
    {
        [JsonPropertyName("tcId")]
        public int? TcId { get; set; }

        [JsonPropertyName("deferred")]
        public bool? Deferred { get; set; }

        [JsonPropertyName("sk")]
        public string Sk { get; set; }

        [JsonPropertyName("pk")]
        public string Pk { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("context")]
        public string Context { get; set; }

        [JsonPropertyName("hashAlg")]
        public string HashAlg { get; set; }

        [JsonPropertyName("additionalRandomness")]
        public string? AdditionalRandomness { get; set; }

        [JsonPropertyName("signature")]
        public string Signature { get; set; }
    }

    public class TestGroup
    {
        [JsonPropertyName("tgId")]
        public int? TgId { get; set; }

        [JsonPropertyName("testType")]
        public string TestType { get; set; }

        [JsonPropertyName("parameterSet")]
        public string ParameterSet { get; set; }

        [JsonPropertyName("deterministic")]
        public bool? Deterministic { get; set; }

        [JsonPropertyName("signatureInterface")]
        public string SignatureInterface { get; set; }

        [JsonPropertyName("preHash")]
        public string PreHash { get; set; }

        [JsonPropertyName("tests")]
        public List<Test> Tests { get; set; }
    }



}
