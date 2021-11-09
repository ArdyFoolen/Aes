using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class GcmEncryptorFactory : IAesFactory
    {
        private AesManager aesManager = new AesManager();
        private IAuthenticatedCryptoTransform transform;
        private AesSettings Settings { get; set; }
        private byte[] Aad { get; set; }
        public string Tag { get; set; } = null;
        public GcmEncryptorFactory(AesSettings settings, byte[] aad)
        {
            Settings = settings;
            Aad = aad;
        }

        public ICryptoTransform CreateEncryptor()
        {
            transform = aesManager.CreateGcmEncryptor(Settings.Key, Settings.IV, Aad, Settings.KeySize);
            return transform;
        }

        public ICryptoTransform CreateDecryptor()
            => aesManager.CreateGcmDecryptor(Settings.Key, Settings.IV, Aad, Tag ?? transform?.Tag ?? string.Empty, Settings.KeySize);
    }
}
