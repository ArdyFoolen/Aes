using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF
{
    public static class PaddingFactory
    {
        public static Func<int, int, byte> GetPaddingFunction(PaddingMode mode)
        {
            switch (mode)
            {
                case PaddingMode.PKCS7:
                    return (NumberOfBytes, CurrentByte) => (byte)NumberOfBytes;
                case PaddingMode.Zeros:
                    return (NumberOfBytes, CurrentByte) => CurrentByte == 0 ? (byte)0x80 : (byte)0x00;
                case PaddingMode.ANSIX923:
                    return (NumberOfBytes, CurrentByte) => NumberOfBytes == CurrentByte ? (byte)NumberOfBytes : (byte)0x00;
                case PaddingMode.ISO10126:
                    return (NumberOfBytes, CurrentByte) => NumberOfBytes == CurrentByte ? (byte)NumberOfBytes : RandomByte();
            }
            return null;
        }

        public static Func<byte[], int, int> GetRemovePaddingFunction(PaddingMode mode)
        {
            switch (mode)
            {
                case PaddingMode.PKCS7:
                case PaddingMode.ANSIX923:
                case PaddingMode.ISO10126:
                    return (Buffer, Length) => (int)Buffer[Length - 1];
                case PaddingMode.Zeros:
                    return (Buffer, Length) => Buffer.Reverse().Select((b, i) => new { value = b, index = i }).First(f => f.value == 0x80).index;
            }
            return null;
        }

        private static byte RandomByte()
        {
            var random = new Random();
            return (byte)random.Next(0, 0xff);
        }
    }
}
