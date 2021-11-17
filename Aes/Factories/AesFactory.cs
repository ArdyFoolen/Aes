using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Aes.AF.Factories
{
    public class AesFactory : IAesFactory
    {
        public IEncryptorFactory CreateFactory(EncryptModeEnum mode, byte[] aad = null)
        {
            var settings = AesSettings.GetEnumerator();

            switch(mode)
            {
                case EncryptModeEnum.ECB:
                    return new EcbEncryptorFactory(settings.FirstOrDefault(s => EncryptModeEnum.ECB.Equals(s.Mode)));
                case EncryptModeEnum.CBC:
                    return new CbcEncryptorFactory(settings.FirstOrDefault(s => EncryptModeEnum.CBC.Equals(s.Mode)));
                case EncryptModeEnum.CTR:
                    return new CtrEncryptorFactory(settings.FirstOrDefault(s => EncryptModeEnum.CTR.Equals(s.Mode)));
                case EncryptModeEnum.GCM:
                    return new GcmEncryptorFactory(settings.FirstOrDefault(s => EncryptModeEnum.GCM.Equals(s.Mode)), aad);
                default:
                    throw new ArgumentOutOfRangeException($"Invalid Mode {mode}");
            }
        }
    }
}
