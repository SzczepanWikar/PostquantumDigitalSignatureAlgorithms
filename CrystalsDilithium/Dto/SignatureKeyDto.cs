namespace CrystalsDilithium.Dto
{
    public sealed record SignatureKeyDto(
        byte[] Rho,
        byte[] K,
        byte[] Tr,
        int[][] S1,
        int[][] S2,
        int[][] T0
    );
}
