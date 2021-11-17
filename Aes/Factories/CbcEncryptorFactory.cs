using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class CbcEncryptorFactory : EncryptorFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public CbcEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public override ICryptoTransform CreateEncryptor()
            => aesManager.CreateCbcEncryptor(Settings.Key, Settings.IV, Settings.KeySize);

        public override ICryptoTransform CreateDecryptor()
            => aesManager.CreateCbcDecryptor(Settings.Key, Settings.IV, Settings.KeySize);
    }
}
