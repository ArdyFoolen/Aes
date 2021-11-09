using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class CbcEncryptorFactory : IAesFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public CbcEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public ICryptoTransform CreateEncryptor()
            => aesManager.CreateCbcEncryptor(Settings.Key, Settings.IV, Settings.KeySize);

        public ICryptoTransform CreateDecryptor()
            => aesManager.CreateCbcDecryptor(Settings.Key, Settings.IV, Settings.KeySize);
    }
}
