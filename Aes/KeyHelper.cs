using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF
{
    public static class KeyHelper
    {
        public static byte[] GetKey(this string key, AesKeySize keySize)
            => key.GetKey((int)keySize / 8);

        public static byte[] GetKey(this string key, int keySize)
        {
            string keyFmt = string.Format("{{0, -{0}}}", keySize);
            if (keySize < key.Length)
                return Encoding.ASCII.GetBytes(string.Format(keyFmt, key.Substring(0, keySize)));
            else
                return Encoding.ASCII.GetBytes(string.Format(keyFmt, key));
        }
    }
}
