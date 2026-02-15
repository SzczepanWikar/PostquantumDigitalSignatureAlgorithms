using System.Security.Cryptography;

namespace Core.PlatformImplementation
{
    public sealed class Fips204Facade : IPostQuantumSignature, IDisposable
    {
        private static readonly MLDsaAlgorithm _mLDsaAlgorithm = MLDsaAlgorithm.MLDsa44;
        private MLDsa? _signingAlgorithm;
        private MLDsa? _verifyingAlgorithm;
        private bool _disposed = false;

        public Fips204Facade()
        {
            _signingAlgorithm = _verifyingAlgorithm = MLDsa.GenerateKey(_mLDsaAlgorithm);
        }

        public Fips204Facade(byte[] publicKey, byte[] privateKey)
        {
            ArgumentNullException.ThrowIfNull(publicKey);
            ArgumentNullException.ThrowIfNull(privateKey);

            if (publicKey.Length == 0)
                throw new ArgumentException("Public key cannot be empty.", nameof(publicKey));

            if (privateKey.Length == 0)
                throw new ArgumentException("Private key cannot be empty.", nameof(privateKey));

            _verifyingAlgorithm = MLDsa.ImportMLDsaPublicKey(_mLDsaAlgorithm, publicKey);
            _signingAlgorithm = MLDsa.ImportMLDsaPrivateKey(_mLDsaAlgorithm, privateKey);
        }

        public (byte[] PublicKey, byte[] PrivateKey) ExportKeys()
        {
            ThrowIfDisposed();

            byte[] publicKey = _verifyingAlgorithm!.ExportMLDsaPublicKey();
            byte[] privateKey = _signingAlgorithm!.ExportMLDsaPrivateKey();

            return (publicKey, privateKey);
        }

        public (byte[] PublicKey, byte[] PrivateKey) GenerateKeyPair()
        {
            ThrowIfDisposed();

            _signingAlgorithm?.Dispose();
            _verifyingAlgorithm?.Dispose();

            _signingAlgorithm = _verifyingAlgorithm = MLDsa.GenerateKey(_mLDsaAlgorithm);

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
            ObjectDisposedException.ThrowIf(_disposed, nameof(Fips204Facade));
            ArgumentNullException.ThrowIfNull(_signingAlgorithm);
            ArgumentNullException.ThrowIfNull(_verifyingAlgorithm);
        }
    }
}
