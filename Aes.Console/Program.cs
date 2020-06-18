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
            using (AF.Aes aes = new AF.Aes(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192))
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
            using (AF.Aes aes = new AF.Aes(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192))
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

            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192))
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
            using (AF.Aes aes = new AF.Aes(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192, AesEnDecrypt.Decrypt))
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
