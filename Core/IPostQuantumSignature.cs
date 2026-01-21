namespace Core
{
    public interface IPostQuantumSignature
    {
        (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair();
        byte[] Sign(ReadOnlySpan<byte> message);
        bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature);
        (byte[] PublicKey, byte[] PrivateKey) ExportKeys();
    }
}
