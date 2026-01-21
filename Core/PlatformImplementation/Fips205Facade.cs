
namespace Core.PlatformImplementation
{
    public sealed class Fips205Facade : IPostQuantumSignature
    {
        public (byte[] PublicKey, byte[] PrivateKey) ExportKeys()
        {
            throw new NotImplementedException();
        }

        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            throw new NotImplementedException();
        }

        public byte[] Sign(ReadOnlySpan<byte> message)
        {
            throw new NotImplementedException();
        }

        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            throw new NotImplementedException();
        }
    }
}
