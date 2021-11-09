using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF.Extensions
{
    public static class ByteExtensions
    {
        public static byte[] Copy(this byte[] array)
        {
            byte[] copy = new byte[array.Length];
            Array.Copy(array, copy, copy.Length);
            return copy;
        }
    }
}
