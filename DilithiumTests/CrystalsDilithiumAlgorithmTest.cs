using System.Security.Cryptography;
using System.Text;
using Core.PreHashing;
using CrystalsDilithium;

namespace DilithiumTests
{
    namespace CrystalsDilithiumTest
    {
        public class CrystalsDilithiumAlgorithmTest
        {
            public static IEnumerable<object[]> SecurityLevels =>
                [
                    [DilithiumParametersProvider.SecurityLevel2Parameters, MLDsaAlgorithm.MLDsa44],
                    [DilithiumParametersProvider.SecurityLevel3Parameters, MLDsaAlgorithm.MLDsa65],
                    [DilithiumParametersProvider.SecurityLevel5Parameters, MLDsaAlgorithm.MLDsa87],
                ];

            public static IEnumerable<object[]> SigningProceduresSecurityLevels => SecurityLevels.Select(e => new[] { e[0] });

            public static IEnumerable<object[]> SigningProcedurePreHashSecurityLevels =>
                from e in SigningProceduresSecurityLevels
                from ph in Enum.GetValues<PreHashFunction>()
                select new object[] { e[0], ph };

            [Theory]
            [MemberData(nameof(SecurityLevels))]
            public void CrystalsDilithiumAlgorithm_KeyGen_GeneratedKeysAreCompatibleWithReferenceImplementation(DilithiumParameters parameters, MLDsaAlgorithm mlDsaAlgorithm)
            {
                //Arrange
                CrystalsDilithiumAlgorithm algorithm = new CrystalsDilithiumAlgorithm(parameters);

                var (pk, sk) = algorithm.KeyGen();

                MLDsa veryfyingReferenceAlgorithm = MLDsa.ImportMLDsaPublicKey(mlDsaAlgorithm, pk);
                MLDsa signingReferenceAlgorithm = MLDsa.ImportMLDsaPrivateKey(mlDsaAlgorithm, sk);

                // Act
                byte[] message = Encoding.UTF8.GetBytes("Document");

                byte[] signature = signingReferenceAlgorithm.SignData(message);

                bool isValid = veryfyingReferenceAlgorithm.VerifyData(message, signature);

                // Assert
                Assert.True(isValid);
            }

            [Theory]
            [MemberData(nameof(SecurityLevels))]
            public void CrystalsDilithiumAlgorithm_Sign_SignIsCompatibleWithReferenceImplementation(DilithiumParameters parameters, MLDsaAlgorithm mlDsaAlgorithm)
            {
                //Arrange
                CrystalsDilithiumAlgorithm algorithm = new CrystalsDilithiumAlgorithm(parameters);

                MLDsa referenceAlgorithm = MLDsa.GenerateKey(mlDsaAlgorithm);
                byte[] sk = referenceAlgorithm.ExportMLDsaPrivateKey();

                // Act
                byte[] message = Encoding.UTF8.GetBytes("Document");

                byte[] signature = algorithm.Sign(sk, message);

                bool isValid = referenceAlgorithm.VerifyData(message, signature);

                // Assert
                Assert.True(isValid);
            }

            [Theory]
            [MemberData(nameof(SecurityLevels))]
            public void CrystalsDilithiumAlgorithm_Verify_VerifyIsCompatibleWithReferenceImplementation(DilithiumParameters parameters, MLDsaAlgorithm mlDsaAlgorithm)
            {
                // Arrange
                CrystalsDilithiumAlgorithm algorithm = new CrystalsDilithiumAlgorithm(parameters);

                MLDsa referenceAlgorithm = MLDsa.GenerateKey(mlDsaAlgorithm);
                byte[] pk = referenceAlgorithm.ExportMLDsaPublicKey();

                // Act
                byte[] message = Encoding.UTF8.GetBytes("Document");

                byte[] signature = referenceAlgorithm.SignData(message);

                bool isValid = algorithm.Verify(pk, message, signature);

                // Assert
                Assert.True(isValid);
            }

            [Theory]
            [MemberData(nameof(SigningProceduresSecurityLevels))]
            public void CrystalsDilithiumAlgorithm_SigningProcedure(DilithiumParameters parameters)
            {
                CrystalsDilithiumAlgorithm algorithm = new CrystalsDilithiumAlgorithm(parameters);

                var (pk, sk) = algorithm.KeyGen();

                byte[] message = Encoding.UTF8.GetBytes("Document");

                byte[] signature = algorithm.Sign(sk, message);

                bool isValid = algorithm.Verify(pk, message, signature);

                Assert.True(isValid);
            }

            [Theory]
            [MemberData(nameof(SigningProcedurePreHashSecurityLevels))]
            public void CrystalsDilithiumAlgorithm_SigningProcedure_PreHash(
                DilithiumParameters parameters,
                PreHashFunction preHashFunction
            )
            {
                CrystalsDilithiumAlgorithm algorithm = new CrystalsDilithiumAlgorithm(parameters);

                var (pk, sk) = algorithm.KeyGen();

                byte[] message = Encoding.UTF8.GetBytes("Document");

                byte[] signature = algorithm.Sign(sk, message, preHashFunction);

                bool isValid = algorithm.Verify(pk, message, signature, preHashFunction);

                Assert.True(isValid);
            }
        }
    }
}
