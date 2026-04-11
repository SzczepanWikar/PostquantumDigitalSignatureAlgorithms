using System.Text.Json.Serialization;

namespace SphincsPlusTests.KAT.Models.KeyGeneration
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
        public List<TestGroup> TestGroups { get; set; } = [];
    }

    public class Test
    {
        [JsonPropertyName("tcId")]
        public int? TcId { get; set; }

        [JsonPropertyName("deferred")]
        public bool? Deferred { get; set; }

        [JsonPropertyName("skSeed")]
        public string SkSeed { get; set; }

        [JsonPropertyName("skPrf")]
        public string SkPrf { get; set; }

        [JsonPropertyName("pkSeed")]
        public string PkSeed { get; set; }

        [JsonPropertyName("sk")]
        public string Sk { get; set; }

        [JsonPropertyName("pk")]
        public string Pk { get; set; }
    }

    public class TestGroup
    {
        [JsonPropertyName("tgId")]
        public int? TgId { get; set; }

        [JsonPropertyName("testType")]
        public string TestType { get; set; }

        [JsonPropertyName("parameterSet")]
        public string ParameterSet { get; set; }

        [JsonPropertyName("tests")]
        public List<Test> Tests { get; set; } = [];
    }


}
