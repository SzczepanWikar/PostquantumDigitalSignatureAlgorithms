using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace DilithiumTests.KAT.Models.Verifying
{
    // Root myDeserializedClass = JsonSerializer.Deserialize<Root>(myJsonResponse);
     internal class InternalProjection
    {
        [JsonPropertyName("vsId")]
        public int VsId { get; set; }

        [JsonPropertyName("algorithm")]
        public string Algorithm { get; set; }

        [JsonPropertyName("mode")]
        public string Mode { get; set; }

        [JsonPropertyName("revision")]
        public string Revision { get; set; }

        [JsonPropertyName("isSample")]
        public bool IsSample { get; set; }

        [JsonPropertyName("testGroups")]
        public List<TestGroup> TestGroups { get; set; }
    }

     internal class Test
    {
        [JsonPropertyName("tcId")]
        public int TcId { get; set; }

        [JsonPropertyName("testPassed")]
        public bool TestPassed { get; set; }

        [JsonPropertyName("deferred")]
        public bool Deferred { get; set; }

        [JsonPropertyName("pk")]
        public string Pk { get; set; }

        [JsonPropertyName("sk")]
        public string Sk { get; set; }

        [JsonPropertyName("message")]
        public string Message { get; set; }

        [JsonPropertyName("context")]
        public string Context { get; set; }

        [JsonPropertyName("hashAlg")]
        public string HashAlg { get; set; }

        [JsonPropertyName("signature")]
        public string Signature { get; set; }

        [JsonPropertyName("reason")]
        public string Reason { get; set; }

        [JsonPropertyName("mu")]
        public string Mu { get; set; }
    }

     internal class TestGroup
    {
        [JsonPropertyName("tgId")]
        public int TgId { get; set; }

        [JsonPropertyName("testType")]
        public string TestType { get; set; }

        [JsonPropertyName("parameterSet")]
        public string ParameterSet { get; set; }

        [JsonPropertyName("signatureInterface")]
        public string SignatureInterface { get; set; }

        [JsonPropertyName("preHash")]
        public string PreHash { get; set; }

        [JsonPropertyName("externalMu")]
        public bool ExternalMu { get; set; }

        [JsonPropertyName("tests")]
        public List<Test> Tests { get; set; }
    }


}
