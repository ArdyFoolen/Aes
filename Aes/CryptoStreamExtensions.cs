using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF
{
    public static class CryptoStreamExtensions
    {
        public static void WriteFrom(this CryptoStream crypto, Stream reader)
        {
            byte[] plaintext = new byte[0x400];
            int bytesRead;
            do
            {
                bytesRead = reader.Read(plaintext, 0, 0x400);
                crypto.Write(plaintext, 0, bytesRead);
            } while (bytesRead == 0x400);
        }

        public static void ReadInto(this CryptoStream crypto, Stream writer)
        {
            byte[] ciphertext = new byte[0x400];
            int bytesRead;
            do
            {
                bytesRead = crypto.Read(ciphertext, 0, ciphertext.Length);
                writer.Write(ciphertext, 0, bytesRead);
            } while (bytesRead > 0x0);
        }
    }
}
