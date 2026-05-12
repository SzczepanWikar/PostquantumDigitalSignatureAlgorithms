using System.Security.Cryptography;
using BenchmarkDotNet.Attributes;

namespace Benchmarks;

[MemoryDiagnoser]
public class MlDsaReferenceBenchmarks
{
    [Params(2, 3, 5)]
    public int SecurityLevel { get; set; }

    private MLDsaAlgorithm _mlDsaAlgorithm;
    private MLDsa _mlDsa = null!;
    private byte[] _message = null!;
    private byte[] _signature = null!;

    [GlobalSetup]
    public void Setup()
    {
        _mlDsaAlgorithm = SecurityLevel switch
        {
            2 => MLDsaAlgorithm.MLDsa44,
            3 => MLDsaAlgorithm.MLDsa65,
            5 => MLDsaAlgorithm.MLDsa87,
            _ => throw new ArgumentOutOfRangeException(nameof(SecurityLevel)),
        };

        _message = "Document"u8.ToArray();
        _mlDsa = MLDsa.GenerateKey(_mlDsaAlgorithm);
        _signature = _mlDsa.SignData(_message);
    }

    [GlobalCleanup]
    public void Cleanup() => _mlDsa.Dispose();

    [Benchmark]
    public (byte[], byte[]) KeyGen()
    {
        using MLDsa mlDsa = MLDsa.GenerateKey(_mlDsaAlgorithm);
        return (mlDsa.ExportMLDsaPublicKey(), mlDsa.ExportMLDsaPrivateKey());
    }

    [Benchmark]
    public byte[] Sign() => _mlDsa.SignData(_message);

    [Benchmark]
    public bool Verify() => _mlDsa.VerifyData(_message, _signature);
}
