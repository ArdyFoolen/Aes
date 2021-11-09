using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF.Factories
{
    public interface IEncryptorFactory
    {
        IAesFactory CreateFactory(EncryptModeEnum mode, byte[] aad = null);
    }
}
