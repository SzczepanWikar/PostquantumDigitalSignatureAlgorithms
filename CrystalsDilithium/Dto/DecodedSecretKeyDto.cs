namespace CrystalsDilithium.Dto
{
    public sealed record DecodedSecretKeyDto(
        byte[] Rho,
        byte[] K,
        byte[] Tr,
        int[][] S1,
        int[][] S2,
        int[][] T0
    );
}
