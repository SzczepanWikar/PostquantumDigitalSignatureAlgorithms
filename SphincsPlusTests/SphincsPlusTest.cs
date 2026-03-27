using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using SphincsPlus;
using System.Text;

namespace SphincsPlusTests
{
    public class SphincsPlusTest
    {
        public static IEnumerable<object[]> ParameterSets =>
            [
                [SphincsPlusParametersProvider.Sha2_128s, SlhDsaParameters.slh_dsa_sha2_128s],
                [SphincsPlusParametersProvider.Sha2_128f, SlhDsaParameters.slh_dsa_sha2_128f],
                [SphincsPlusParametersProvider.Shake_128s, SlhDsaParameters.slh_dsa_shake_128s],
                [SphincsPlusParametersProvider.Shake_128f, SlhDsaParameters.slh_dsa_shake_128f],
                [SphincsPlusParametersProvider.Sha2_192s, SlhDsaParameters.slh_dsa_sha2_192s],
                [SphincsPlusParametersProvider.Sha2_192f, SlhDsaParameters.slh_dsa_sha2_192f],
                [SphincsPlusParametersProvider.Shake_192s, SlhDsaParameters.slh_dsa_shake_192s],
                [SphincsPlusParametersProvider.Shake_192f, SlhDsaParameters.slh_dsa_shake_192f],
                [SphincsPlusParametersProvider.Sha2_256s, SlhDsaParameters.slh_dsa_sha2_256s],
                [SphincsPlusParametersProvider.Sha2_256f, SlhDsaParameters.slh_dsa_sha2_256f],
                [SphincsPlusParametersProvider.Shake_256s, SlhDsaParameters.slh_dsa_shake_256s],
                [SphincsPlusParametersProvider.Shake_256f, SlhDsaParameters.slh_dsa_shake_256f],
            ];

        [Theory]
        [MemberData(nameof(ParameterSets))]
        public void SphincsPlusAlgorithm_KeyGen_GeneratedKeysAreCompatibleWithReferenceImplementation(
            SphincsPlusParameters parameters,
            SlhDsaParameters bcParams
        )
        {
            // Arrange
            SphincsPlusAlgorithm algorithm = new SphincsPlusAlgorithm(parameters);

            var (sk, pk) = algorithm.KeyGen();

            var bcPublicKey = SlhDsaPublicKeyParameters.FromEncoding(bcParams, pk);
            var bcPrivateKey = SlhDsaPrivateKeyParameters.FromEncoding(bcParams, sk);

            byte[] message = Encoding.UTF8.GetBytes("Document");

            // Act
            var signer = new SlhDsaSigner(bcParams, false);
            signer.Init(true, bcPrivateKey);
            signer.BlockUpdate(message, 0, message.Length);
            byte[] signature = signer.GenerateSignature();

            var verifier = new SlhDsaSigner(bcParams, false);
            verifier.Init(false, bcPublicKey);
            verifier.BlockUpdate(message, 0, message.Length);
            bool isValid = verifier.VerifySignature(signature);

            // Assert
            Assert.True(isValid);
        }
    }
}
