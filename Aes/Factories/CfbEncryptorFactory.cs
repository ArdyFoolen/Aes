using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class CfbEncryptorFactory : EncryptorFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public CfbEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public override ICryptoTransform CreateEncryptor()
            => aesManager.CreateCfbEncryptor(Settings.GetKey(), Settings.IV, Settings.KeySize, Settings.FeedbackSize);

        public override ICryptoTransform CreateDecryptor()
            => aesManager.CreateCfbDecryptor(Settings.GetKey(), Settings.IV, Settings.KeySize, Settings.FeedbackSize);
    }
}
