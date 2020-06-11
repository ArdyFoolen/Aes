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
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        public static byte GMul(byte a, byte b)
        {
            byte p = 0;

            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                    p ^= a;

                bool isHighBitSet = (a & 0x80) != 0;
                a <<= 1;

                if (isHighBitSet)
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

                b >>= 1;
            }

            return p;
        }

        #endregion
    }
}
