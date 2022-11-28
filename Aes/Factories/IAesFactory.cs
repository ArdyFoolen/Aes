using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF.Factories
{
    public interface IAesFactory
    {
#if NET6_0
        IEncryptorFactory CreateFactory(EncryptModeEnum mode, byte[] aad = null);
#endif
        IEncryptorFactory CreateFactory(AesSettings settings, byte[] aad = null);
    }
}
