using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public class GcmEncryptorFactory : EncryptorFactory
    {
        private AesManager aesManager = new AesManager();
        public IAuthenticatedCryptoTransform transform;
        private AesSettings Settings { get; set; }
        private byte[] Aad { get; set; }

        private string tag = null;
        public string Tag { get { return tag ?? transform?.Tag ?? string.Empty; } set { tag = value; } }
        public GcmEncryptorFactory(AesSettings settings, byte[] aad)
        {
            Settings = settings;
            Aad = aad;
        }

        public override ICryptoTransform CreateEncryptor()
        {
            transform = aesManager.CreateGcmEncryptor(Settings.Key, Settings.IV, Aad, Settings.KeySize);
            return transform;
        }

        public override ICryptoTransform CreateDecryptor()
            => aesManager.CreateGcmDecryptor(Settings.Key, Settings.IV, Aad, Tag, Settings.KeySize);
    }
}
