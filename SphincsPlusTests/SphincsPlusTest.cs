using System.Text;
using Core.PreHashing;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using SphincsPlus;

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
            from p in KeyGenParameterSets
            from deterministic in new[] { true, false }
            select new object[] { p[0], p[1], deterministic };

        public static IEnumerable<object[]> SigningProcedureParameterSets =>
            ParameterSets.Select(p => new object[] { p[0], p[2] });

        public static IEnumerable<object[]> SigningProcedurePreHashParameterSets =>
            from p in ParameterSets
            from ph in Enum.GetValues<PreHashFunction>()
            select new object[] { p[0], p[2], ph };

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
                new SlhDsaKeyGenerationParameters(
                    new Org.BouncyCastle.Security.SecureRandom(),
                    bcParams
                )
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
                new SlhDsaKeyGenerationParameters(
                    new Org.BouncyCastle.Security.SecureRandom(),
                    bcParams
                )
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

        [Theory]
        [MemberData(nameof(SigningProcedureParameterSets))]
        public void SphincsPlusAlgorithm_SigningProcedure(
            SphincsPlusParameters parameters,
            bool deterministic
        )
        {
            SphincsPlusAlgorithm algorithm = new(parameters, deterministic);

            var (sk, pk) = algorithm.KeyGen();

            byte[] message = Encoding.UTF8.GetBytes("Document");

            byte[] signature = algorithm.Sign(message, [], sk);

            bool isValid = algorithm.Verify(message, signature, [], pk);

            Assert.True(isValid);
        }

        [Theory]
        [MemberData(nameof(SigningProcedurePreHashParameterSets))]
        public void SphincsPlusAlgorithm_SigningProcedure_PreHash(
            SphincsPlusParameters parameters,
            bool deterministic,
            PreHashFunction preHashFunction
        )
        {
            SphincsPlusAlgorithm algorithm = new(parameters, deterministic);

            var (sk, pk) = algorithm.KeyGen();

            byte[] message = Encoding.UTF8.GetBytes("Document");

            byte[] signature = algorithm.Sign(message, [], preHashFunction, sk);

            bool isValid = algorithm.Verify(message, signature, [], preHashFunction, pk);

            Assert.True(isValid);
        }
    }
}
