using CrystalsDilithium;
using System.Security.Cryptography;
using System.Text;

namespace DilithiumTests
{

    namespace CrystalsDilithiumTest
    {
        public class CrystalsDilithiumAlgorithmTest
        {
            [Fact]
            public void CrystalsDilithiumAlgorithm_KeyGen_GeneratedKeysAreCompatibleWithReferenceImpelementation()
            {
                //Arrange
                DilithiumParameters parameters = DilithiumParametersProvider.SecurityLevel2Parameters;
                CrystalsDilithiumAlgorithm algorithm = new CrystalsDilithiumAlgorithm(parameters);

                var (pk, sk) = algorithm.KeyGen();

                MLDsaAlgorithm mLDsaAlgorithm = MLDsaAlgorithm.MLDsa44;
                MLDsa veryfyingReferenceAlgorithm = MLDsa.ImportMLDsaPublicKey(mLDsaAlgorithm, pk);
                MLDsa signingReferenceAlgorithm = MLDsa.ImportMLDsaPrivateKey(mLDsaAlgorithm, sk);

                // Act
                byte[] message = Encoding.UTF8.GetBytes("interop-test");

                byte[] signature = signingReferenceAlgorithm.SignData(message);

                bool isValid = veryfyingReferenceAlgorithm.VerifyData(message, signature);

                // Assert
                Assert.True(isValid);
            }
        }
    }

}
