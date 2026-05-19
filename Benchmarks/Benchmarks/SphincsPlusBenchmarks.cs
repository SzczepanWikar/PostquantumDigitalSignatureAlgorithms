using BenchmarkDotNet.Attributes;
using SphincsPlus;

namespace Benchmarks;

[MemoryDiagnoser]
public class SphincsPlusBenchmarks
{
    [Params(
        "Shake_128f",
        "Shake_128s",
        "Shake_192f",
        "Shake_192s",
        "Shake_256f",
        "Shake_256s",
        "Sha2_128f",
        "Sha2_128s",
        "Sha2_192f",
        "Sha2_192s",
        "Sha2_256f",
        "Sha2_256s"
    )]
    public string ParameterSet { get; set; } = null!;

    private SphincsPlusAlgorithm _algorithm = null!;
    private byte[] _pk = null!;
    private byte[] _sk = null!;
    private byte[] _message = null!;
    private byte[] _ctx = null!;
    private byte[] _signature = null!;

    [GlobalSetup]
    public void Setup()
    {
        SphincsPlusParameters parameters = ParameterSet switch
        {
            "Shake_128f" => SphincsPlusParametersProvider.Shake_128f,
            "Shake_128s" => SphincsPlusParametersProvider.Shake_128s,
            "Shake_192f" => SphincsPlusParametersProvider.Shake_192f,
            "Shake_192s" => SphincsPlusParametersProvider.Shake_192s,
            "Shake_256f" => SphincsPlusParametersProvider.Shake_256f,
            "Shake_256s" => SphincsPlusParametersProvider.Shake_256s,
            "Sha2_128f" => SphincsPlusParametersProvider.Sha2_128f,
            "Sha2_128s" => SphincsPlusParametersProvider.Sha2_128s,
            "Sha2_192f" => SphincsPlusParametersProvider.Sha2_192f,
            "Sha2_192s" => SphincsPlusParametersProvider.Sha2_192s,
            "Sha2_256f" => SphincsPlusParametersProvider.Sha2_256f,
            "Sha2_256s" => SphincsPlusParametersProvider.Sha2_256s,
            _ => throw new ArgumentOutOfRangeException(nameof(ParameterSet)),
        };

        _algorithm = new SphincsPlusAlgorithm(parameters, deterministic: false);
        _message = "Document"u8.ToArray();
        _ctx = [];

        (_sk, _pk) = _algorithm.KeyGen();
        _signature = _algorithm.Sign(_message, _ctx, _sk);
    }

    [Benchmark]
    public (byte[], byte[]) KeyGen() => _algorithm.KeyGen();

    [Benchmark]
    public byte[] Sign() => _algorithm.Sign(_message, _ctx, _sk);

    [Benchmark]
    public bool Verify() => _algorithm.Verify(_message, _signature, _ctx, _pk);
}
