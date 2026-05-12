using BenchmarkDotNet.Attributes;
using CrystalsDilithium;

namespace Benchmarks;

[MemoryDiagnoser]
public class DilithiumBenchmarks
{
    [Params(2, 3, 5)]
    public int SecurityLevel { get; set; }

    private CrystalsDilithiumAlgorithm _algorithm = null!;
    private byte[] _pk = null!;
    private byte[] _sk = null!;
    private byte[] _message = null!;
    private byte[] _signature = null!;

    [GlobalSetup]
    public void Setup()
    {
        DilithiumParameters parameters = SecurityLevel switch
        {
            2 => DilithiumParametersProvider.SecurityLevel2Parameters,
            3 => DilithiumParametersProvider.SecurityLevel3Parameters,
            5 => DilithiumParametersProvider.SecurityLevel5Parameters,
            _ => throw new ArgumentOutOfRangeException(nameof(SecurityLevel)),
        };

        _algorithm = new CrystalsDilithiumAlgorithm(parameters);
        _message = "Document"u8.ToArray();

        (_pk, _sk) = _algorithm.KeyGen();
        _signature = _algorithm.Sign(_sk, _message);
    }

    [Benchmark]
    public (byte[], byte[]) KeyGen() => _algorithm.KeyGen();

    [Benchmark]
    public byte[] Sign() => _algorithm.Sign(_sk, _message);

    [Benchmark]
    public bool Verify() => _algorithm.Verify(_pk, _message, _signature);
}
