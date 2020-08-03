using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Aes.AF;

namespace Aes.App
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] a = new byte[] { 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] b = new byte[] { 0x38, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            byte[] z = GaloisMultiplication.GMul128(a, b);
            byte[] x = new byte[] { 0xab, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            for (int i = 0; i < 128; i++)
            {
                //a = GaloisMultiplication.GMul1282(a, a);
                x = GaloisMultiplication.GMul128(x, x);
            }

            // Tests
            // Commutative: val1 * val2 = val2 * val1
            // Distributive: (x+y)*z = (x*z) + (y*z) Addition is XOR
            // Square x 128 times = x

            byte r1 = GaloisMultiplication.GMul(0xab, 0xab);
            byte r2 = GaloisMultiplication.GMul(r1, r1);
            byte r3 = GaloisMultiplication.GMul(r2, r2);
            byte r4 = GaloisMultiplication.GMul(r3, r3);
            byte r5 = GaloisMultiplication.GMul(r4, r4);
            byte r6 = GaloisMultiplication.GMul(r5, r5);
            byte r7 = GaloisMultiplication.GMul(r6, r6);
            byte r8 = GaloisMultiplication.GMul(r7, r7);

            byte r = 0xab;
            for (int i = 0; i < 8; i++)
                r = GaloisMultiplication.GMul(r, r);

            // ab * ab 8x = ab
            // 1010 1011 * 1010 1011 = 1011 0011    1
            // 1011 0011 * 1011 0011 = 1110 1000    2
            // 1110 1000 * 1110 1000 = 0001 1101    3
            // 0001 1101 * 0001 1101 = 0100 1010    4
            // 0100 1010 * 0100 1010 = 1110 1111    5
            // 1110 1111 * 1110 1111 = 0000 1000    6
            // 0000 1000 * 0000 1000 = 0100 0000    7
            // 0100 0000 * 0100 0000 = 1010 1011    8

            // 0101 0110            1   1010 1011   0110 0110       1   1011 0011   1101 0000       8   0000 0001   0011 1010 2x    1   0001 1101
            // 0001 1011            2   0100 1101   0001 1011       2   0111 1101   0001 1011       32  0000 0100   0111 0100 4x    4   0111 0100
            // 0100 1101 2x         8   0010 1111   0111 1101 2x    16  1100 0101   1100 1011 2x    64  0000 1000   1110 1000 8x    8   1110 1000
            // 1001 1010 4x         32  1011 1100   1111 1010 4x    32  1001 0001   1001 0110       128 0001 0000   1101 0000       16  1100 1011
            // 0011 0100            128 1100 0110   1111 0100       128 0111 0010   0001 1011       =   0001 1101   0001 1011       =   0100 1010
            // 0001 1011            =   1011 0011   0001 1011       =   1110 1000   1000 1101 4x                    1100 1011 16x
            // 0010 1111 8x                         1110 1111 8x                    0001 1010                       1001 0110
            // 0101 1110 16x                        1101 1110                       0001 1011                       0001 1011
            // 1011 1100 32x                        0001 1011                       0000 0001 8x                    1000 1101 32x
            // 0111 1000                            1100 0101 16x                   0000 0010 16x                   0001 1010
            // 0001 1011                            1000 1010                       0000 0100 32x                   0001 1011
            // 0110 0011 64x                        0001 1011                       0000 1000 64x                   0000 0001 64x
            // 1100 0110 128x                       1001 0001 32x                   0001 0000 128x                  0000 0010 128x
            //                                      0010 0010
            //                                      0001 1011
            //                                      0011 1001 64x
            //                                      0111 0010 128x

            // 1001 0100 2x 2   1001 0100 1101 1110     1   1110 1111   0001 0000 2x    8   0100 0000   1000 0000 2x    64  1010 1011
            // 0010 1000    8   0110 0110 0001 1011     2   1100 0101   0010 0000 4x                    0001 1011 4x
            // 0001 1011    64  0001 1101 1100 0101 2x  4   1001 0001   0100 0000 8x                    0011 0110 8x
            // 0011 0011 4x =   1110 1111 1000 1010     8   0011 1001   1000 0000 16x                   0110 1100 16x
            // 0110 0110 8x               0001 1011     32  1110 0100   0000 0000                       1101 1000 32x
            // 1100 1100 16x              1001 0001 4x  64  1101 0011   0001 1011 32x                   1011 0000
            // 1001 1000                  0010 0010     128 1011 1101   0010 0110 64x                   0001 1011
            // 0001 1011                  0001 1011     =   0000 1000   0100 1100 128x                  1010 1011 64x
            // 1000 0011 32x              0011 1001 8x
            // 0000 0110                  0111 0010 16x
            // 0001 1011                  1110 0100 32x
            // 0001 1101 64x              1100 1000
            //                            0001 1011
            //                            1101 0011 64x
            //                            1010 0110
            //                            0001 1011
            //                            1011 1101 128x

            AF.Aes aes = new AF.Aes();

            // ECB encryption
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aes.CreateEncryptor(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }

            // ECB decryption
            using (Stream stream = new FileStream("EncryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aes.CreateDecryptor(GetKey("Thats my Kung Fu", 24), AesKeySize.Aes192), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
            }

            // CBC encryption
            byte[] IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedCBCFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aes.CreateEncryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CBC, AesKeySize.Aes128), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }

            // CBC decryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00 };
            using (Stream stream = new FileStream("EncryptedCBCFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedCBCFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aes.CreateDecryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CBC, AesKeySize.Aes128), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
            }

            // CTR encryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c };
            using (Stream stream = new FileStream("UnencryptedFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("EncryptedCTRFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(writer, aes.CreateEncryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CTR, AesKeySize.Aes128), CryptoStreamMode.Write))
            {
                encryptStream.WriteFrom(stream);
            }

            // CTR decryption
            IV = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x01, 0x0b, 0x0c };
            using (Stream stream = new FileStream("EncryptedCTRFile.txt", FileMode.Open))
            using (FileStream writer = new FileStream("DecryptedCTRFile.txt", FileMode.Create))
            using (var encryptStream = new CryptoStream(stream, aes.CreateDecryptor(GetKey("Thats my Kung Fu", 16), IV, EncryptModeEnum.CTR, AesKeySize.Aes128), CryptoStreamMode.Read))
            {
                encryptStream.ReadInto(writer);
            }

            Console.ReadKey();
        }

        private static byte[] GetKey(string key, int keySize)
        {
            string keyFmt = string.Format("{{0, -{0}}}", keySize);
            if (keySize < key.Length)
                return Encoding.ASCII.GetBytes(string.Format(keyFmt, key.Substring(0, keySize)));
            else
                return Encoding.ASCII.GetBytes(string.Format(keyFmt, key));
        }
    }
}
