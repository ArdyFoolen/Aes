﻿using System;
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
            AF.AesManager aesManager = new AF.AesManager();

            // ECB encryption
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aesManager.CreateEncryptor(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }

            // ECB decryption
            using (Stream stream = new FileStream("EncryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aesManager.CreateDecryptor(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
            }

            // CBC encryption
            byte[] IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedCBCFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aesManager.CreateEncryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CBC, AesKeySize.Aes128), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }

            // CBC decryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
            using (Stream stream = new FileStream("EncryptedCBCFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedCBCFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aesManager.CreateDecryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CBC, AesKeySize.Aes128), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
            }

            // CTR encryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c };
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedCTRFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aesManager.CreateEncryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CTR, AesKeySize.Aes128), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }

            // CTR decryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c };
            using (Stream stream = new FileStream("EncryptedCTRFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedCTRFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aesManager.CreateDecryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CTR, AesKeySize.Aes128), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
            }

            // GCM encryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c };
            string ad = "ThisIsMyAuthenticatedDataWhatEverIWantAndHowLongIWant";
            byte[] aad = GetKey(ad, ad.Length);
            IAuthenticatedCryptoTransform transform;
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedGCMFile.txt", FileMode.Create))
            using (transform = aesManager.CreateEncryptor(GetKey("Thats my Kung Fu", 16), IV, aad, AesKeySize.Aes128))
            using (var encryptStream = new CryptoStream(writer, transform, CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }
            string tag = transform.Tag;

            // GCM decryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c };
            ad = "ThisIsMyAuthenticatedDataWhatEverIWantAndHowLongIWant";
            aad = GetKey(ad, ad.Length);
            using (Stream stream = new FileStream("EncryptedGCMFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedGCMFile.txt", FileMode.Create))
            using (transform = aesManager.CreateDecryptor(GetKey("Thats my Kung Fu", 16), IV, aad, tag, AesKeySize.Aes128))
            using (var encryptStream = new CryptoStream(stream, transform, CryptoStreamMode.Read))
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
