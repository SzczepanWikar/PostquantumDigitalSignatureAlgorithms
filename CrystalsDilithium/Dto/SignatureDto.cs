using System.Collections;

namespace CrystalsDilithium.Dto
{
    public sealed record SignatureDto(byte[] CWave, int[][] Z, BitArray[]? H);
}
