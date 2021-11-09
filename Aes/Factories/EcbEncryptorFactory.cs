using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class EcbEncryptorFactory : IAesFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public EcbEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public ICryptoTransform CreateEncryptor()
            => aesManager.CreateEcbEncryptor(Settings.Key, Settings.KeySize);

        public ICryptoTransform CreateDecryptor()
            => aesManager.CreateEcbDecryptor(Settings.Key, Settings.KeySize);
    }
}
