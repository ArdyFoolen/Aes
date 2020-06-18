using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Aes.AF;

namespace Aes.App
{
    class Program
    {
        static void Main(string[] args)
        {
            Func<int, int, byte> PaddingFunction = (NumberOfBytes, CurrentByte) => (byte)NumberOfBytes;
            Func<byte[], int, int> RemovePaddingFunction = (Buffer, Length) => (int)Buffer[Length - 1];

            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192))
            using (FileStream writer = new FileStream("EncryptedFile.txt", FileMode.Create))
            {
                aes.PaddingFunction = PaddingFunction;
                aes.Encrypt(writer);
            }

            using (Stream stream = new FileStream("EncryptedFile.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192))
            using (FileStream writer = new FileStream("DecryptedFile.txt", FileMode.Create))
            {
                aes.RemovePaddingFunction = RemovePaddingFunction;
                aes.Decrypt(writer);
            }

            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192))
            using (FileStream writer = new FileStream("EncryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aes, CryptoStreamMode.Write))
            {
                aes.PaddingFunction = PaddingFunction;
                byte[] plaintext = new byte[0x400];
                int bytesRead;
                do
                {
                    bytesRead = stream.Read(plaintext, 0, 0x400);
                    encryptStream.Write(plaintext, 0, bytesRead);
                } while (bytesRead == 0x400);
            }

            using (Stream stream = new FileStream("EncryptedFile.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192, AesEnDecrypt.Decrypt))
            using (FileStream writer = new FileStream("DecryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aes, CryptoStreamMode.Read))
            {
                aes.RemovePaddingFunction = RemovePaddingFunction;
                byte[] ciphertext = new byte[0x400];
                int bytesRead;
                do
                {
                    bytesRead = encryptStream.Read(ciphertext, 0, ciphertext.Length);
                    writer.Write(ciphertext, 0, bytesRead);
                } while (bytesRead == 0x400);
            }

            // File: 00112233445566778899aabbccddeeff
            // Key: 000102030405060708090a0b0c0d0e0f
            byte[] buffer = new byte[]
            {
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
            };
            byte[] byteKey = new byte[]
            {
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
            };

            using (Stream stream = new FileStream("UnencryptedFile2.txt", FileMode.Create))
            {
                stream.Write(buffer, 0, 16);
            }

            using (Stream stream = new FileStream("UnencryptedFile2.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, byteKey))
            using (FileStream writer = new FileStream("EncryptedFile2.txt", FileMode.Create))
            {
                aes.Encrypt(writer);
            }

            Console.ReadKey();
        }

        private static byte[] GetKey(string key, int keySize)
        {
            string keyFmt = string.Format("{{0, -{0}}}", keySize);
            if (keySize < key.Length)
                return Encoding.ASCII.GetBytes(string.Format(keyFmt, key.Substring(0, keySize)));
            else
                return Encoding.ASCII.GetBytes(string.Format(keyFmt, key));
        }
    }
}
