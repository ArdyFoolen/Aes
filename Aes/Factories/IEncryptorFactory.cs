﻿using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Factories
{
    public interface IEncryptorFactory
    {
        ICryptoTransform CreateEncryptor();
        ICryptoTransform CreateDecryptor();
        string Encrypt(string source);
        string Decrypt(string source);
    }
}
