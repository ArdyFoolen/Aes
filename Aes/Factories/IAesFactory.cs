using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF.Factories
{
    public interface IAesFactory
    {
        IEncryptorFactory CreateFactory(EncryptModeEnum mode, byte[] aad = null);
        IEncryptorFactory CreateFactory(AesSettings settings, byte[] aad = null);
    }
}
