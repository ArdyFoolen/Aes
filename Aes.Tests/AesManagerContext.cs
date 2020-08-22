using Aes.AF;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes.Tests
{
    public class AesManagerContext : AesManager
    {
        private Aes aes;
        public AesManagerContext()
        {
            aes = new Aes();
        }

        public AesManagerContext(byte[] byteKey, AesKeySize keySize = AesKeySize.Aes128)
        {
            aes = new Aes(byteKey, keySize);
        }

        public int RoundKeyLength
        {
            get => aes.RoundKey.Length;
        }

        public byte[] GetRoundKey(int index)
            => aes.RoundKey[index];

        public void InitializeKey()
        {
            aes.InitializeRoundKey();
        }

        public int ExecutingRound { get; private set; } = 0;
        public byte[] AddRoundKey(byte[] input, byte[] key)
        {
            byte[] result = aes.AddRoundKey(input, key);
            return result;
        }
    }
}
