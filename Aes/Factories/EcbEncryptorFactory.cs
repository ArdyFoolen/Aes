using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class EcbEncryptorFactory : EncryptorFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public EcbEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public override ICryptoTransform CreateEncryptor()
            => aesManager.CreateEcbEncryptor(Settings.GetKey(), Settings.KeySize);

        public override ICryptoTransform CreateDecryptor()
            => aesManager.CreateEcbDecryptor(Settings.GetKey(), Settings.KeySize);
    }
}
