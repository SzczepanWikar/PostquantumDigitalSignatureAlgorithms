using Core.Helpers;
using SphincsPlus.Algorithms;

namespace SphincsPlus
{
    internal sealed class Adrs
    {
        public byte[] Content { get; private set; } = new byte[32];

        public Adrs()
        {}

        public Adrs(byte[] content)
        {
            if(content.Length != 32)
            {
                throw new ArgumentException("Content length must be 32.");
            }

            Content = content;
        }

        public void SetLayerAddress(int l)
        {
            byte[] layer = ByteConversions.ToByte(l, 4);

            byte[] postfix = Content.Skip(4).ToArray();

            Content = ByteArrayHelpers.ConcatBytes(layer, postfix);
        }

        public void SetTreeAddress(int t)
        {
            byte[] layer = Content.Take(4).ToArray();
            byte[] tree = ByteConversions.ToByte(t, 12);
            byte[] postfix = Content.Skip(16).ToArray();

            Content = ByteArrayHelpers.ConcatBytes(layer, tree, postfix);
        }

        public void SetTypeAndClear(int y)
        {
            byte[] prefix = Content.Take(16).ToArray();
            byte[] type = ByteConversions.ToByte(y, 4);
            byte[] postfix = new byte[12];

            Content = ByteArrayHelpers.ConcatBytes(prefix, type, postfix);
        }

        public void SetKeyPairAddress(int i)
        {
            byte[] prefix = Content.Take(20).ToArray();
            byte[] keyPair = ByteConversions.ToByte(i, 4);
            byte[] postfix = Content.Skip(24).ToArray();

            Content = ByteArrayHelpers.ConcatBytes(prefix, keyPair, postfix);
        }

        public void SetChainAddress(int i)
        {
            byte[] prefix = Content.Take(24).ToArray();
            byte[] chain = ByteConversions.ToByte(i, 4);
            byte[] postfix = Content.Skip(28).ToArray();

            Content = ByteArrayHelpers.ConcatBytes(prefix, chain, postfix);
        }

        public void SetTreeHeight(int i) => SetChainAddress(i);

        public void SetHashAddress(int i)
        {
            byte[] prefix = Content.Take(28).ToArray();
            byte[] hash = ByteConversions.ToByte(i, 4);

            Content = ByteArrayHelpers.ConcatBytes(prefix, hash);
        }
        public void SetTreeIndex(int i) => SetHashAddress(i);

        public long GetKeyPairAddress() => ByteConversions.ToInt64(Content[20..24]);
        public long GetTreeIndex() => ByteConversions.ToInt64(Content[28..32]);
    }
}
