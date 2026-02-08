namespace Core.Helpers
{
    public static class BoolExtensions
    {
        public static byte ToByte(this bool b) => b ? (byte)1 : (byte)0;
        public static int ToInt32(this bool b) => b ? 1 : 0;
    }
}
