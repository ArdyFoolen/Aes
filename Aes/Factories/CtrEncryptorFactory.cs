using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class CtrEncryptorFactory : IAesFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public CtrEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public ICryptoTransform CreateEncryptor()
            => aesManager.CreateCtrEncryptor(Settings.Key, Settings.IV, Settings.KeySize);

        public ICryptoTransform CreateDecryptor()
            => aesManager.CreateCtrDecryptor(Settings.Key, Settings.IV, Settings.KeySize);
    }
}
