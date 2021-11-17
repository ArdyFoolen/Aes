using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Aes.AF;
using Aes.AF.Factories;

namespace Aes.App
{
    class Program
    {
        static void Main(string[] args)
        {
            string unencrypted = "This is an unencrypted text, to be encrypted by AES";

            Environment.SetEnvironmentVariable(AesSettings.AesSettingsEnvPath, "Configs\\AesSettings.json");
            IEncryptorFactory encryptorFactory = new EncryptorFactory();

            // ECB encryption
            IAesFactory factory = encryptorFactory.CreateFactory(EncryptModeEnum.ECB);
            Encrypt("UnencryptedFile.txt", "EncryptedFile.txt", factory);

            // ECB decryption
            Decrypt("EncryptedFile.txt", "DecryptedFile.txt", factory);

            var decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // CBC encryption
            factory = encryptorFactory.CreateFactory(EncryptModeEnum.CBC);
            Encrypt("UnencryptedFile.txt", "EncryptedCBCFile.txt", factory);

            // CBC decryption
            Decrypt("EncryptedCBCFile.txt", "DecryptedCBCFile.txt", factory);

            decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // CTR encryption
            factory = encryptorFactory.CreateFactory(EncryptModeEnum.CTR);
            Encrypt("UnencryptedFile.txt", "EncryptedCTRFile.txt", factory);

            // CTR decryption
            Decrypt("EncryptedCTRFile.txt", "DecryptedCTRFile.txt", factory);

            decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // GCM encryption
            string ad = "ThisIsMyAuthenticatedDataWhatEverIWantAndHowLongIWant";
            byte[] aad = KeyHelper.GetKey(ad, ad.Length);
            factory = encryptorFactory.CreateFactory(EncryptModeEnum.GCM, aad);
            Encrypt("UnencryptedFile.txt", "EncryptedGCMFile.txt", factory);

            // GCM decryption
            Decrypt("EncryptedGCMFile.txt", "DecryptedGCMFile.txt", factory);

            decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");
        }

        private static void Encrypt(string sourceFile, string targetFile, IAesFactory factory)
        {
            using (Stream stream = new FileStream(sourceFile, FileMode.Open))
            using (Stream writer = new FileStream(targetFile, FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, factory.CreateEncryptor(), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }
        }

        private static void Decrypt(string sourceFile, string targetFile, IAesFactory factory)
        {
            using (Stream stream = new FileStream(sourceFile, FileMode.Open))
            using (Stream writer = new FileStream(targetFile, FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, factory.CreateDecryptor(), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
            }
        }
    }
}
