using BenchmarkDotNet.Attributes;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;

namespace Benchmarks;

[MemoryDiagnoser]
public class SlhDsaReferenceBenchmarks
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

    private SlhDsaParameters _bcParams = null!;
    private SlhDsaPrivateKeyParameters _privateKey = null!;
    private SlhDsaPublicKeyParameters _publicKey = null!;
    private byte[] _message = null!;
    private byte[] _signature = null!;

    [GlobalSetup]
    public void Setup()
    {
        _bcParams = ParameterSet switch
        {
            "Shake_128f" => SlhDsaParameters.slh_dsa_shake_128f,
            "Shake_128s" => SlhDsaParameters.slh_dsa_shake_128s,
            "Shake_192f" => SlhDsaParameters.slh_dsa_shake_192f,
            "Shake_192s" => SlhDsaParameters.slh_dsa_shake_192s,
            "Shake_256f" => SlhDsaParameters.slh_dsa_shake_256f,
            "Shake_256s" => SlhDsaParameters.slh_dsa_shake_256s,
            "Sha2_128f" => SlhDsaParameters.slh_dsa_sha2_128f,
            "Sha2_128s" => SlhDsaParameters.slh_dsa_sha2_128s,
            "Sha2_192f" => SlhDsaParameters.slh_dsa_sha2_192f,
            "Sha2_192s" => SlhDsaParameters.slh_dsa_sha2_192s,
            "Sha2_256f" => SlhDsaParameters.slh_dsa_sha2_256f,
            "Sha2_256s" => SlhDsaParameters.slh_dsa_sha2_256s,
            _ => throw new ArgumentOutOfRangeException(nameof(ParameterSet)),
        };

        var generator = new SlhDsaKeyPairGenerator();
        generator.Init(new SlhDsaKeyGenerationParameters(new SecureRandom(), _bcParams));
        var keyPair = generator.GenerateKeyPair();
        _privateKey = (SlhDsaPrivateKeyParameters)keyPair.Private;
        _publicKey = (SlhDsaPublicKeyParameters)keyPair.Public;

        _message = "Document"u8.ToArray();

        var signer = new SlhDsaSigner(_bcParams, false);
        signer.Init(true, _privateKey);
        signer.BlockUpdate(_message, 0, _message.Length);
        _signature = signer.GenerateSignature();
    }

    [Benchmark]
    public (SlhDsaPrivateKeyParameters, SlhDsaPublicKeyParameters) KeyGen()
    {
        var generator = new SlhDsaKeyPairGenerator();
        generator.Init(new SlhDsaKeyGenerationParameters(new SecureRandom(), _bcParams));
        var keyPair = generator.GenerateKeyPair();
        return ((SlhDsaPrivateKeyParameters)keyPair.Private, (SlhDsaPublicKeyParameters)keyPair.Public);
    }

    [Benchmark]
    public byte[] Sign()
    {
        var signer = new SlhDsaSigner(_bcParams, false);
        signer.Init(true, _privateKey);
        signer.BlockUpdate(_message, 0, _message.Length);
        return signer.GenerateSignature();
    }

    [Benchmark]
    public bool Verify()
    {
        var verifier = new SlhDsaSigner(_bcParams, false);
        verifier.Init(false, _publicKey);
        verifier.BlockUpdate(_message, 0, _message.Length);
        return verifier.VerifySignature(_signature);
    }
}
