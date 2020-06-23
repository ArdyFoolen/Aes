using Aes.AF;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aes.Tests
{
    public class AesContext : Aes.AF.Aes
    {
        public AesContext() : base() { }
        public AesContext(byte[] byteKey, AesKeySize keySize = AesKeySize.Aes128) : base(byteKey, keySize) { }

        public int RoundKeyLength
        {
            get => RoundKey.Length;
        }

        public byte[] GetRoundKey(int index)
            => RoundKey[index];

        public void InitializeKey()
        {
            base.InitializeRoundKey();
        }

        public int ExecutingRound { get; private set; } = 0;
        protected override byte[] AddRoundKey(byte[] input, byte[] key)
        {
            byte[] result = base.AddRoundKey(input, key);
            return result;
        }

        protected override byte[] ByteSubstitution(byte[] input)
        {
            byte[] result = base.ByteSubstitution(input);
            return result;
        }

        protected override byte[] ShiftRows(byte[] input)
        {
            byte[] result = base.ShiftRows(input);
            return result;
        }

        protected override byte[] MixColumns(byte[] input)
        {
            byte[] result = base.MixColumns(input);
            return result;
        }

        protected override byte[] EncryptRound(byte[] input, byte[] key)
        {
            ExecutingRound += 1;
            byte[] result = base.EncryptRound(input, key);
            return result;
        }
    }
}
