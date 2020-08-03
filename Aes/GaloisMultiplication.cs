using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF
{
    public static class GaloisMultiplication
    {
        #region Galois Field (256) Multiplication of two Bytes

        // TestVectors
        // Before       After
        // db 13 53 45  8e 4d a1 bc
        // f2 0a 22 5c  9f dc 58 9d
        // 01 01 01 01  01 01 01 01
        // c6 c6 c6 c6  c6 c6 c6 c6
        // d4 d4 d4 d5  d5 d5 d7 d6
        // 2d 26 31 4c  4d 7e bd f8

        /// <summary>
        /// Galois Field (256) Multiplication of two Bytes
        /// Do not use branches, to avoid side channels
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte GMul(byte a, byte b)
        {
            byte p = 0;
            for (int counter = 0; counter < 8; counter++)
            {
                p ^= (byte)(-(b & 1) & a);
                byte mask = (byte)(-((a >> 7) & 1));
                a = (byte)((a << 1) ^ (0x1b & mask));
                b >>= 1;
            }
            return p;
        }

        #endregion

        #region Galois Field (256) Multiplication of two Bytes

        // TestVectors
        // Before       After
        // db 13 53 45  8e 4d a1 bc
        // f2 0a 22 5c  9f dc 58 9d
        // 01 01 01 01  01 01 01 01
        // c6 c6 c6 c6  c6 c6 c6 c6
        // d4 d4 d4 d5  d5 d5 d7 d6
        // 2d 26 31 4c  4d 7e bd f8

        /// <summary>
        /// Galois Field (256) Multiplication of two Bytes
        /// Do not use branches, to avoid side channels
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte[] GMul128(byte[] a, byte[] b)
        {
            byte[] z = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] v = new byte[a.Length];
            Array.Copy(a, 0, v, 0, a.Length);

            for (int counter = 0; counter < 128; counter++)
            {
                byte mask = (byte)(-((b[counter / 8] >> (7 - (counter % 8))) & 1));
                AddToFirst(z, v, mask);
                mask = (byte)(-(v[v.Length - 1] & 1));
                ShiftRight(v);
                v[0] ^= (byte)(0xe1 & mask);
            }

            return z;
        }

        private static void AddToFirst(byte[] first, byte[] add, byte mask)
        {
            for (int i = 0; i < first.Length; i++)
                first[i] ^= (byte)(add[i] & mask);
        }

        private static void ShiftRight(byte[] y)
        {
            for (int i = y.Length - 1; i > 0; i--)
                y[i] = (byte)(((y[i] >> 1)) | ((y[i - 1] << 7) & 0x80));
            y[0] >>= 1;
        }

        #endregion
    }
}
