using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Core.PreHashing
{
    public static class PreHasher
    {
        public static (byte[] oid, byte[] phM) PreHashMessage(
            byte[] msg,
            PreHashFunction preHashFunction
        )
        {
            return preHashFunction switch
            {
                PreHashFunction.Sha256 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01],
                    SHA256.HashData(msg)
                ),
                PreHashFunction.Sha512 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03],
                    SHA512.HashData(msg)
                ),
                PreHashFunction.Shake128 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B],
                    Shake128.HashData(msg, 32)
                ),
                PreHashFunction.Shake256 => (
                    [0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C],
                    Shake256.HashData(msg, 64)
                ),
                _ => throw new NotSupportedException("PreHashFunction not supported"),
            };
        }
    }
}
