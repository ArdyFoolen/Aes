using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF
{
    public static class GaloisMultiplication
    {
        #region Galois Field 2(8) Finit Field Multiplication with reducer 0x11B

        // TestVectors
        // Before       After
        // db 13 53 45  8e 4d a1 bc
        // f2 0a 22 5c  9f dc 58 9d
        // 01 01 01 01  01 01 01 01
        // c6 c6 c6 c6  c6 c6 c6 c6
        // d4 d4 d4 d5  d5 d5 d7 d6
        // 2d 26 31 4c  4d 7e bd f8

        /// <summary>
        /// Galois Field 2(8) Finit Field Multiplication with reducer 0x11B
        /// Method is used in the MixColumns of Aes Encryption and Decryption
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

        #region Galois Field 2(128) Multiplication of two Byte arrays with reducer (x128 + x7 + x2 + x + 1)

        /// <summary>
        /// Galois Field 2(128) Multiplication of two Byte arrays with reducer (x128 + x7 + x2 + x + 1)
        /// Method is used in Galois Counter Mode (GCM) Authenticated Encryption with Authenticated Data (AEAD)
        /// Do not use branches, to avoid side channels
        /// Note: unlike the GMul method the multiplication is a shift right and overflow is on the least significant bit 
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

        public static byte[] Add(byte[] a, byte[] b)
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
