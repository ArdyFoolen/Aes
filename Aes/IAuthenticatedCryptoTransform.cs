using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF
{
    public interface IAuthenticatedCryptoTransform : ICryptoTransform
    {
        string Tag { get; }
    }
}
