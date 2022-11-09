using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class OfbEncryptorFactory : EncryptorFactory
    {
        private AesManager aesManager = new AesManager();
        private AesSettings Settings { get; set; }

        public OfbEncryptorFactory(AesSettings settings)
        {
            Settings = settings;
        }

        public override ICryptoTransform CreateEncryptor()
            => aesManager.CreateOfbEncryptor(Settings.GetKey(), Settings.IV, Settings.KeySize, Settings.FeedbackSize);

        public override ICryptoTransform CreateDecryptor()
            => aesManager.CreateOfbDecryptor(Settings.GetKey(), Settings.IV, Settings.KeySize, Settings.FeedbackSize);
    }
}
