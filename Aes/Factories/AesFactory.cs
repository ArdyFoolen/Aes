using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using static Aes.AF.Extensions.StreamExtensions;
using static Aes.AF.Extensions.UsingExtensions;

namespace Aes.AF.Factories
{
    public abstract class AesFactory : IAesFactory
    {
        public abstract ICryptoTransform CreateDecryptor();

        public abstract ICryptoTransform CreateEncryptor();

        public string Encrypt(string source)
            => MemoryStream(source)
                .Using(m => MemoryStream()
                .Using(w =>
                {
                    CryptoStream(w, CreateEncryptor(), CryptoStreamMode.Write).Using(c => c.WriteFrom(m));
                    w.Position = 0;
                    return StreamReader(w).Using(r => r.ReadToEnd());
                }));

        public string Decrypt(string source)
            => MemoryStream(source)
                .Using(m => MemoryStream()
                .Using(w =>
                {
                    CryptoStream(m, CreateDecryptor(), CryptoStreamMode.Read).Using(c => c.ReadInto(w));
                    w.Position = 0;
                    return StreamReader(w).Using(r => r.ReadToEnd());
                }));
    }
}
