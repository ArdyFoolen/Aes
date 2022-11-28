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
            IAesFactory aesFactory = new AesFactory();

            // ECB encryption
            IEncryptorFactory factory = aesFactory.CreateFactory(EncryptModeEnum.ECB);
            Encrypt("UnencryptedFile.txt", "EncryptedFile.txt", factory);

            // ECB decryption
            Decrypt("EncryptedFile.txt", "DecryptedFile.txt", factory);

            var decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // CBC encryption
            factory = aesFactory.CreateFactory(EncryptModeEnum.CBC);
            Encrypt("UnencryptedFile.txt", "EncryptedCBCFile.txt", factory);

            // CBC decryption
            Decrypt("EncryptedCBCFile.txt", "DecryptedCBCFile.txt", factory);

            decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // CTR encryption
            factory = aesFactory.CreateFactory(EncryptModeEnum.CTR);
            Encrypt("UnencryptedFile.txt", "EncryptedCTRFile.txt", factory);

            // CTR decryption
            Decrypt("EncryptedCTRFile.txt", "DecryptedCTRFile.txt", factory);

            decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // GCM encryption
            string ad = "ThisIsMyAuthenticatedDataWhatEverIWantAndHowLongIWant";
            byte[] aad = KeyHelper.GetKey(ad, ad.Length);
            factory = aesFactory.CreateFactory(EncryptModeEnum.GCM, aad);
            Encrypt("UnencryptedFile.txt", "EncryptedGCMFile.txt", factory);

            // GCM decryption
            Decrypt("EncryptedGCMFile.txt", "DecryptedGCMFile.txt", factory);

            // Cannot use the following way in a networking environment
            // When I encrypt I save the generated Tag in the factory
            // The decryption process then uses this Tag to authenticate the decryption
            decrypted = factory.Decrypt(factory.Encrypt(unencrypted));
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // Networking example
            GcmEncryptorFactory gcmFactory = factory as GcmEncryptorFactory;
            string gcmEncrypted = factory.Encrypt(unencrypted);
            string gcmTag = gcmFactory.Tag;

            GcmEncryptorFactory remoteGcmFactory = aesFactory.CreateFactory(EncryptModeEnum.GCM, aad) as GcmEncryptorFactory;
            remoteGcmFactory.Tag = gcmTag;
            decrypted = remoteGcmFactory.Decrypt(gcmEncrypted);
            if (!unencrypted.Equals(decrypted))
                throw new Exception("Encrypt and Decrypt not succeeded");

            // Test for VideoPlayer
            // C:\Users\afoolen\source\repos\VideoPlayer\VideoPlayer\TestFiles\sample-mp4-file.mp4
            // GCM encryption
            ad = "sample-mp4-file.mp4";
            aad = KeyHelper.GetKey(ad, ad.Length);
            gcmFactory = aesFactory.CreateFactory(EncryptModeEnum.GCM, aad) as GcmEncryptorFactory;
            Encrypt("C:\\Users\\afoolen\\source\\repos\\VideoPlayer\\VideoPlayer\\TestFiles\\sample-mp4-file.mp4",
                "C:\\Users\\afoolen\\source\\repos\\VideoPlayer\\VideoPlayerApp\\Encrypted\\sample-mp4-file.eaf", gcmFactory);
            gcmTag = gcmFactory.Tag;
        }

        private static void Encrypt(string sourceFile, string targetFile, IEncryptorFactory factory)
        {
            using (Stream stream = new FileStream(sourceFile, FileMode.Open))
            using (Stream writer = new FileStream(targetFile, FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, factory.CreateEncryptor(), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }
        }

        private static void Decrypt(string sourceFile, string targetFile, IEncryptorFactory factory)
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
