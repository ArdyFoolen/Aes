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
            AF.Aes aes = new AF.Aes();

            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aes.CreateEncryptor(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }

            using (Stream stream = new FileStream("EncryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aes.CreateDecryptor(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
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
