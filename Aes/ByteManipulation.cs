using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF
{
    public static class ByteManipulation
    {
        /// <summary>
        /// Xor operation on byte arrays
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte[] Add(this byte[] a, byte[] b)
        {
            int l = (a?.Length ?? 0) > (b?.Length ?? 0) ? a.Length : b.Length;
            byte[] result = new byte[l];
            for (int i = 0; i < l; i++)
            {
                byte first = i < (a?.Length ?? 0) ? a[i] : (byte)0x00;
                byte second = i < (b?.Length ?? 0) ? b[i] : (byte)0x00;
                result[i] = (byte)(first ^ second);
            }
            return result;
        }

        public static void AddToFirst(this byte[] first, byte[] add, byte mask)
        {
            for (int i = 0; i < first.Length; i++)
                first[i] ^= (byte)(add[i] & mask);
        }

        public static void ShiftRight(this byte[] y, int shift = 1)
        {
            for (int s = 0; s < shift; s++)
            {
                for (int i = y.Length - 1; i > 0; i--)
                    y[i] = (byte)(((y[i] >> 1)) | ((y[i - 1] << 7) & 0x80));
                y[0] >>= 1;
            }
        }

        public static void ShiftLeft(this byte[] y, int shift = 1)
        {
            for (int s = 0; s < shift; s++)
            {
                for (int i = 0; i < y.Length - 1; i++)
                    y[i] = (byte)(((y[i] << 1)) | ((y[i + 1] >> 7) & 0x01));
                y[y.Length - 1] <<= 1;
            }
        }
    }
}
