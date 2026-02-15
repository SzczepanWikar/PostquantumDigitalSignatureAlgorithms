namespace Core.Helpers
{
    public static class ByteArrayHelpers
    {
        public static byte[] ConcatBytes(params byte[][] parts)
        {
            if (parts == null)
                throw new ArgumentNullException(nameof(parts));

            int totalLength = 0;
            for (int i = 0; i < parts.Length; i++)
            {
                if (parts[i] == null)
                    throw new ArgumentNullException($"parts[{i}]");

                totalLength += parts[i].Length;
            }

            byte[] result = new byte[totalLength];

            int offset = 0;
            for (int i = 0; i < parts.Length; i++)
            {
                Buffer.BlockCopy(parts[i], 0, result, offset, parts[i].Length);
                offset += parts[i].Length;
            }

            return result;
        }
    }
}
