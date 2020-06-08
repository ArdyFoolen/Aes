using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Aes.AF;

namespace Aes.App
{
    class Program
    {
        static void Main(string[] args)
        {
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, "Thats my Kung Fu"))
            using (FileStream writer = new FileStream("EncryptedFile.txt", FileMode.Create))
            {
                aes.Encrypt(writer);
            }

            using (Stream stream = new FileStream("EncryptedFile.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, "Thats my Kung Fu"))
            using (FileStream writer = new FileStream("DecryptedFile.txt", FileMode.Create))
            {
                aes.Decrypt(writer);
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

            using (Stream stream = new FileStream("EncryptedFile2.txt", FileMode.Open))
            using (AF.Aes aes = new AF.Aes(stream, "000102030405060708090a0b0c0d0e0f"))
            using (FileStream writer = new FileStream("DecryptedFile2.txt", FileMode.Create))
            {
                aes.Decrypt(writer);
            }

            Console.ReadKey();
        }
    }
}
