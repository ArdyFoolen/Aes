using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class CtrEncryptorFactory : EncryptorFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public CtrEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public override ICryptoTransform CreateEncryptor()
            => aesManager.CreateCtrEncryptor(Settings.Key, Settings.IV, Settings.KeySize);

        public override ICryptoTransform CreateDecryptor()
            => aesManager.CreateCtrDecryptor(Settings.Key, Settings.IV, Settings.KeySize);
    }
}
