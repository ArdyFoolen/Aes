﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Aes.AF.Factories
{
    public class AesFactory : IAesFactory
    {
        public IEncryptorFactory CreateFactory(EncryptModeEnum mode, byte[] aad = null)
        {
            var settings = AesSettings.GetEnumerator()
                .FirstOrDefault(s => s.Mode.Equals(mode));
            return CreateFactory(settings, aad);
        }

        public IEncryptorFactory CreateFactory(AesSettings settings, byte[] aad = null)
        {
            switch (settings.Mode)
            {
                case EncryptModeEnum.ECB:
                    return new EcbEncryptorFactory(settings);
                case EncryptModeEnum.CBC:
                    return new CbcEncryptorFactory(settings);
                case EncryptModeEnum.CTR:
                    return new CtrEncryptorFactory(settings);
                case EncryptModeEnum.GCM:
                    return new GcmEncryptorFactory(settings, aad);
                default:
                    throw new ArgumentOutOfRangeException($"Invalid Mode {settings.Mode}");
            }
        }
    }
}
