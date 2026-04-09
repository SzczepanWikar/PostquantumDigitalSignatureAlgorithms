using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using SphincsPlus;
using System.Text;

namespace SphincsPlusTests
{
    public class SphincsPlusTest
    {
        public static IEnumerable<object[]> KeyGenParameterSets =>
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

        public static IEnumerable<object[]> ParameterSets =>
            [
                [SphincsPlusParametersProvider.Sha2_128s, SlhDsaParameters.slh_dsa_sha2_128s, true],
                [SphincsPlusParametersProvider.Sha2_128s, SlhDsaParameters.slh_dsa_sha2_128s, false],
                [SphincsPlusParametersProvider.Sha2_128f, SlhDsaParameters.slh_dsa_sha2_128f, true],
                [SphincsPlusParametersProvider.Sha2_128f, SlhDsaParameters.slh_dsa_sha2_128f, false],
                [SphincsPlusParametersProvider.Shake_128s, SlhDsaParameters.slh_dsa_shake_128s, true],
                [SphincsPlusParametersProvider.Shake_128s, SlhDsaParameters.slh_dsa_shake_128s, false],
                [SphincsPlusParametersProvider.Shake_128f, SlhDsaParameters.slh_dsa_shake_128f, true],
                [SphincsPlusParametersProvider.Shake_128f, SlhDsaParameters.slh_dsa_shake_128f, false],
                [SphincsPlusParametersProvider.Sha2_192s, SlhDsaParameters.slh_dsa_sha2_192s, true],
                [SphincsPlusParametersProvider.Sha2_192s, SlhDsaParameters.slh_dsa_sha2_192s, false],
                [SphincsPlusParametersProvider.Sha2_192f, SlhDsaParameters.slh_dsa_sha2_192f, true],
                [SphincsPlusParametersProvider.Sha2_192f, SlhDsaParameters.slh_dsa_sha2_192f, false],
                [SphincsPlusParametersProvider.Shake_192s, SlhDsaParameters.slh_dsa_shake_192s, true],
                [SphincsPlusParametersProvider.Shake_192s, SlhDsaParameters.slh_dsa_shake_192s, false],
                [SphincsPlusParametersProvider.Shake_192f, SlhDsaParameters.slh_dsa_shake_192f, true],
                [SphincsPlusParametersProvider.Shake_192f, SlhDsaParameters.slh_dsa_shake_192f, false],
                [SphincsPlusParametersProvider.Sha2_256s, SlhDsaParameters.slh_dsa_sha2_256s, true],
                [SphincsPlusParametersProvider.Sha2_256s, SlhDsaParameters.slh_dsa_sha2_256s, false],
                [SphincsPlusParametersProvider.Sha2_256f, SlhDsaParameters.slh_dsa_sha2_256f, true],
                [SphincsPlusParametersProvider.Sha2_256f, SlhDsaParameters.slh_dsa_sha2_256f, false],
                [SphincsPlusParametersProvider.Shake_256s, SlhDsaParameters.slh_dsa_shake_256s, true],
                [SphincsPlusParametersProvider.Shake_256s, SlhDsaParameters.slh_dsa_shake_256s, false],
                [SphincsPlusParametersProvider.Shake_256f, SlhDsaParameters.slh_dsa_shake_256f, true],
                [SphincsPlusParametersProvider.Shake_256f, SlhDsaParameters.slh_dsa_shake_256f, false],
            ];

        [Theory]
        [MemberData(nameof(KeyGenParameterSets))]
        public void SphincsPlusAlgorithm_KeyGen_GeneratedKeysAreCompatibleWithReferenceImplementation(
            SphincsPlusParameters parameters,
            SlhDsaParameters bcParams
        )
        {
            // Arrange
            SphincsPlusAlgorithm algorithm = new SphincsPlusAlgorithm(parameters, false);

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

        [Theory]
        [MemberData(nameof(ParameterSets))]
        public void SphincsPlusAlgorithm_Sign_SignIsCompatibleWithReferenceImplementation(
            SphincsPlusParameters parameters,
            SlhDsaParameters bcParams,
            bool deterministic
        )
        {
            // Arrange
            SphincsPlusAlgorithm algorithm = new SphincsPlusAlgorithm(parameters, deterministic);

            var bcKeyPairGenerator = new SlhDsaKeyPairGenerator();
            bcKeyPairGenerator.Init(
                new SlhDsaKeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom(), bcParams)
            );
            var keyPair = bcKeyPairGenerator.GenerateKeyPair();
            var bcPrivateKey = (SlhDsaPrivateKeyParameters)keyPair.Private;
            var bcPublicKey = (SlhDsaPublicKeyParameters)keyPair.Public;

            byte[] sk = bcPrivateKey.GetEncoded();
            byte[] message = Encoding.UTF8.GetBytes("Document");

            // Act
            byte[] signature = algorithm.Sign(message, [], sk);

            var verifier = new SlhDsaSigner(bcParams, deterministic);
            verifier.Init(false, bcPublicKey);
            verifier.BlockUpdate(message, 0, message.Length);
            bool isValid = verifier.VerifySignature(signature);

            // Assert
            Assert.True(isValid);
        }

        [Theory]
        [MemberData(nameof(ParameterSets))]
        public void SphincsPlusAlgorithm_Verify_VerifyIsCompatibleWithReferenceImplementation(
            SphincsPlusParameters parameters,
            SlhDsaParameters bcParams,
            bool deterministic
        )
        {
            // Arrange
            SphincsPlusAlgorithm algorithm = new SphincsPlusAlgorithm(parameters, deterministic);

            var bcKeyPairGenerator = new SlhDsaKeyPairGenerator();
            bcKeyPairGenerator.Init(
                new SlhDsaKeyGenerationParameters(new Org.BouncyCastle.Security.SecureRandom(), bcParams)
            );
            var keyPair = bcKeyPairGenerator.GenerateKeyPair();
            var bcPrivateKey = (SlhDsaPrivateKeyParameters)keyPair.Private;
            var bcPublicKey = (SlhDsaPublicKeyParameters)keyPair.Public;

            byte[] pk = bcPublicKey.GetEncoded();
            byte[] message = Encoding.UTF8.GetBytes("Document");

            var signer = new SlhDsaSigner(bcParams, deterministic);
            signer.Init(true, bcPrivateKey);
            signer.BlockUpdate(message, 0, message.Length);
            byte[] signature = signer.GenerateSignature();

            // Act
            bool isValid = algorithm.Verify(message, signature, [], pk);

            // Assert
            Assert.True(isValid);
        }
    }
}
