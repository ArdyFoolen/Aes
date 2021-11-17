using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF.Extensions
{
    public static class StreamExtensions
    {
        public static MemoryStream MemoryStream()
           => new MemoryStream();

        public static MemoryStream MemoryStream(string source)
        {
            Encoding encoder = Encoding.GetEncoding("ISO-8859-1");
            return MemoryStream(encoder.GetBytes(source));
        }
        public static MemoryStream MemoryStream(byte[] buffer)
            => new MemoryStream(buffer);

        public static StreamReader StreamReader(Stream stream)
            => new StreamReader(stream, Encoding.GetEncoding("ISO-8859-1"));

        public static CryptoStream CryptoStream(Stream stream, ICryptoTransform transform, CryptoStreamMode mode)
            => new CryptoStream(stream, transform, mode, true);
    }
}
