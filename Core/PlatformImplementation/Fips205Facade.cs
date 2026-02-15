using System.Security.Cryptography;

namespace Core.PlatformImplementation
{
#pragma warning disable SYSLIB5006
    public sealed class Fips205Facade : IPostQuantumSignature, IDisposable
    {
        private static readonly SlhDsaAlgorithm _slhDsaAlgorithm = SlhDsaAlgorithm.SlhDsaSha2_128s;

        private SlhDsa? _signingAlgorithm;
        private SlhDsa? _verifyingAlgorithm;
        private bool _disposed = false;

        public Fips205Facade()
        {
            _signingAlgorithm = _verifyingAlgorithm = SlhDsa.GenerateKey(_slhDsaAlgorithm);
        }

        public Fips205Facade(byte[] publicKey, byte[] privateKey)
        {
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(privateKey);

            if (publicKey.Length == 0)
                throw new ArgumentException("Public key cannot be empty.", nameof(publicKey));

            if (privateKey.Length == 0)
                throw new ArgumentException("Private key cannot be empty.", nameof(privateKey));

            _verifyingAlgorithm = SlhDsa.ImportSlhDsaPublicKey(_slhDsaAlgorithm, publicKey);
            _signingAlgorithm = SlhDsa.ImportSlhDsaPrivateKey(_slhDsaAlgorithm, privateKey);
        }

        public (byte[] PublicKey, byte[] PrivateKey) ExportKeys()
        {
            ThrowIfDisposed();

            byte[] publicKey = _verifyingAlgorithm!.ExportSlhDsaPublicKey();
            byte[] privateKey = _signingAlgorithm!.ExportSlhDsaPrivateKey();

            return (publicKey, privateKey);
        }

        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            ThrowIfDisposed();

            _signingAlgorithm?.Dispose();
            _verifyingAlgorithm?.Dispose();

            _signingAlgorithm = _verifyingAlgorithm = SlhDsa.GenerateKey(_slhDsaAlgorithm);

            return ExportKeys();
        }

        public byte[] Sign(ReadOnlySpan<byte> message)
        {
            ThrowIfDisposed();

            return _signingAlgorithm!.SignData(message.ToArray());
        }

        public bool Verify(ReadOnlySpan<byte> message, ReadOnlySpan<byte> signature)
        {
            ThrowIfDisposed();

            return _verifyingAlgorithm!.VerifyData(message, signature);
        }

        public void Dispose()
        {
            _signingAlgorithm?.Dispose();
            _signingAlgorithm = null;

            _verifyingAlgorithm?.Dispose();
            _verifyingAlgorithm = null;

            _disposed = true;
        }

        private void ThrowIfDisposed()
        {
            ObjectDisposedException.ThrowIf(_disposed, nameof(Fips205Facade));
            ArgumentNullException.ThrowIfNull(_signingAlgorithm);
            ArgumentNullException.ThrowIfNull(_verifyingAlgorithm);
        }
    }
#pragma warning restore SYSLIB5006
}
