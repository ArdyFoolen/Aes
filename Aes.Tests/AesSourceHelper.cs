﻿using Aes.AF;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Aes.Tests
{
    public static class AesSourceHelper
    {
        #region EncryptDecrypt

        public static IEnumerable<(byte[] In, byte[] Out, Action<Aes.AF.Aes, Stream, Stream> Crypt)> EncryptDecrypt
        {
            get
            {
                byte[] key128 = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
                byte[] plainBytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
                byte[] cryptBytes = new byte[] { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key128, AesKeySize.Aes128, PaddingMode.None, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key128, AesKeySize.Aes128, PaddingMode.None, outStream, inStream));

                byte[] key192 = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
                plainBytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
                cryptBytes = new byte[] { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91 };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key192, AesKeySize.Aes192, PaddingMode.None, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key192, AesKeySize.Aes192, PaddingMode.None, outStream, inStream));

                byte[] key256 = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
                plainBytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
                cryptBytes = new byte[] { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89 };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key256, AesKeySize.Aes256, PaddingMode.None, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key256, AesKeySize.Aes256, PaddingMode.None, outStream, inStream));
            }
        }

        public static IEnumerable<(byte[] In, byte[] Out, Action<Aes.AF.Aes, Stream, Stream> Crypt)> EncryptDecryptDifferentPadding
        {
            get
            {
                byte[] key128 = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
                byte[] plainBytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
                byte[] cryptBytes = new byte[] { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a, 
                    0x95, 0x4f, 0x64, 0xf2, 0xe4, 0xe8, 0x6e, 0x9e, 0xee, 0x82, 0xd2, 0x02, 0x16, 0x68, 0x48, 0x99 };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key128, AesKeySize.Aes128, PaddingMode.PKCS7, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key128, AesKeySize.Aes128, PaddingMode.PKCS7, outStream, inStream));

                cryptBytes = new byte[] { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
                    0xd5, 0x65, 0xee, 0x30, 0xa4, 0x7f, 0xf4, 0x3e, 0x31, 0xf1, 0x4a, 0x71, 0xbb, 0xf8, 0xbe, 0xb7 };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key128, AesKeySize.Aes128, PaddingMode.ANSIX923, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key128, AesKeySize.Aes128, PaddingMode.ANSIX923, outStream, inStream));

                cryptBytes = new byte[] { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
                    0x43, 0x99, 0x57, 0x2c, 0xd6, 0xea, 0x53, 0x41, 0xb8, 0xd3, 0x58, 0x76, 0xa7, 0x09, 0x8a, 0xf7 };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key128, AesKeySize.Aes128, PaddingMode.Zeros, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key128, AesKeySize.Aes128, PaddingMode.Zeros, outStream, inStream));

                // ToDo Random padding bytes to be tested later
                //cryptBytes = new byte[] { 0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
                //    0xe8, 0x92, 0x05, 0x75, 0x5e, 0x20, 0x80, 0xf3, 0x9f, 0x7c, 0xe5, 0x1e, 0x08, 0x88, 0xda, 0x16 };
                //yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key128, AesKeySize.Aes128, PaddingMode.ISO10126, outStream, inStream));
                //yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key128, AesKeySize.Aes128, PaddingMode.ISO10126, outStream, inStream));

                byte[] key192 = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17 };
                plainBytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
                cryptBytes = new byte[] { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91, 
                    0x3f, 0xe7, 0x28, 0x6a, 0xbd, 0xe5, 0xf0, 0x39, 0x43, 0xd5, 0x77, 0x70, 0x20, 0x25, 0x96, 0x26 };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key192, AesKeySize.Aes192, PaddingMode.PKCS7, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key192, AesKeySize.Aes192, PaddingMode.PKCS7, outStream, inStream));

                cryptBytes = new byte[] { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
                    0x16, 0x27, 0x11, 0x57, 0xdb, 0x26, 0xb4, 0xc8, 0x5f, 0x85, 0x74, 0xde, 0x3b, 0x3f, 0xe2, 0x0d };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key192, AesKeySize.Aes192, PaddingMode.ANSIX923, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key192, AesKeySize.Aes192, PaddingMode.ANSIX923, outStream, inStream));

                cryptBytes = new byte[] { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
                    0x0d, 0x63, 0xb2, 0xb2, 0xc2, 0x76, 0xde, 0x93, 0x06, 0xb2, 0xf3, 0x7e, 0x36, 0xda, 0xbe, 0x49 };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key192, AesKeySize.Aes192, PaddingMode.Zeros, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key192, AesKeySize.Aes192, PaddingMode.Zeros, outStream, inStream));

                // ToDo Random padding bytes to be tested later
                //cryptBytes = new byte[] { 0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
                //    0x3f, 0xe7, 0x28, 0x6a, 0xbd, 0xe5, 0xf0, 0x39, 0x43, 0xd5, 0x77, 0x70, 0x20, 0x25, 0x96, 0x26 };
                //yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key192, AesKeySize.Aes192, PaddingMode.ISO10126, outStream, inStream));
                //yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key192, AesKeySize.Aes192, PaddingMode.ISO10126, outStream, inStream));

                byte[] key256 = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
                plainBytes = new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
                cryptBytes = new byte[] { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89, 
                    0x9f, 0x3b, 0x75, 0x04, 0x92, 0x6f, 0x8b, 0xd3, 0x6e, 0x31, 0x18, 0xe9, 0x03, 0xa4, 0xcd, 0x4a };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key256, AesKeySize.Aes256, PaddingMode.PKCS7, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key256, AesKeySize.Aes256, PaddingMode.PKCS7, outStream, inStream));

                cryptBytes = new byte[] { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
                    0x2b, 0x34, 0x7c, 0x88, 0xe5, 0xc9, 0xc8, 0xff, 0x0b, 0x7a, 0x12, 0x1b, 0x68, 0x7b, 0xd0, 0x6d };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key256, AesKeySize.Aes256, PaddingMode.ANSIX923, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key256, AesKeySize.Aes256, PaddingMode.ANSIX923, outStream, inStream));

                cryptBytes = new byte[] { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
                    0xe6, 0x20, 0xf5, 0x2f, 0xe7, 0x5b, 0xbe, 0x87, 0xab, 0x75, 0x8c, 0x06, 0x24, 0x94, 0x3d, 0x8b };
                yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key256, AesKeySize.Aes256, PaddingMode.Zeros, outStream, inStream));
                yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key256, AesKeySize.Aes256, PaddingMode.Zeros, outStream, inStream));

                // ToDo Random padding bytes to be tested later
                //cryptBytes = new byte[] { 0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
                //    0x9f, 0x3b, 0x75, 0x04, 0x92, 0x6f, 0x8b, 0xd3, 0x6e, 0x31, 0x18, 0xe9, 0x03, 0xa4, 0xcd, 0x4a };
                //yield return (plainBytes, cryptBytes, (aes, outStream, inStream) => Encrypt(aes, key256, AesKeySize.Aes256, PaddingMode.ISO10126, outStream, inStream));
                //yield return (cryptBytes, plainBytes, (aes, outStream, inStream) => Decrypt(aes, key256, AesKeySize.Aes256, PaddingMode.ISO10126, outStream, inStream));
            }
        }

        private static void Encrypt(AF.Aes aes, byte[] key, AesKeySize keySize, PaddingMode paddingMode, Stream outStream, Stream inStream)
        {
            using (var encryptStream = new CryptoStream(outStream, aes.CreateEncryptor(key, keySize, paddingMode), CryptoStreamMode.Write, true))
            {
                encryptStream.WriteFrom(inStream);
            }
        }

        private static void Decrypt(AF.Aes aes, byte[] key, AesKeySize keySize, PaddingMode paddingMode, Stream outStream, Stream inStream)
        {
            using (var encryptStream = new CryptoStream(inStream, aes.CreateDecryptor(key, keySize, paddingMode), CryptoStreamMode.Read, true))
            {
                encryptStream.ReadInto(outStream);
            }
        }

        #endregion

        #region RoundKeyExpand

        private readonly static byte[][] ExpectedRoundKeys128 = new byte[11][]
        {
            new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c },
            new byte[] { 0xa0, 0xfa, 0xfe, 0x17, 0x88, 0x54, 0x2c, 0xb1, 0x23, 0xa3, 0x39, 0x39, 0x2a, 0x6c, 0x76, 0x05 },
            new byte[] { 0xf2, 0xc2, 0x95, 0xf2, 0x7a, 0x96, 0xb9, 0x43, 0x59, 0x35, 0x80, 0x7a, 0x73, 0x59, 0xf6, 0x7f },
            new byte[] { 0x3d, 0x80, 0x47, 0x7d, 0x47, 0x16, 0xfe, 0x3e, 0x1e, 0x23, 0x7e, 0x44, 0x6d, 0x7a, 0x88, 0x3b },
            new byte[] { 0xef, 0x44, 0xa5, 0x41, 0xa8, 0x52, 0x5b, 0x7f, 0xb6, 0x71, 0x25, 0x3b, 0xdb, 0x0b, 0xad, 0x00 },
            new byte[] { 0xd4, 0xd1, 0xc6, 0xf8, 0x7c, 0x83, 0x9d, 0x87, 0xca, 0xf2, 0xb8, 0xbc, 0x11, 0xf9, 0x15, 0xbc },
            new byte[] { 0x6d, 0x88, 0xa3, 0x7a, 0x11, 0x0b, 0x3e, 0xfd, 0xdb, 0xf9, 0x86, 0x41, 0xca, 0x00, 0x93, 0xfd },
            new byte[] { 0x4e, 0x54, 0xf7, 0x0e, 0x5f, 0x5f, 0xc9, 0xf3, 0x84, 0xa6, 0x4f, 0xb2, 0x4e, 0xa6, 0xdc, 0x4f },
            new byte[] { 0xea, 0xd2, 0x73, 0x21, 0xb5, 0x8d, 0xba, 0xd2, 0x31, 0x2b, 0xf5, 0x60, 0x7f, 0x8d, 0x29, 0x2f },
            new byte[] { 0xac, 0x77, 0x66, 0xf3, 0x19, 0xfa, 0xdc, 0x21, 0x28, 0xd1, 0x29, 0x41, 0x57, 0x5c, 0x00, 0x6e },
            new byte[] { 0xd0, 0x14, 0xf9, 0xa8, 0xc9, 0xee, 0x25, 0x89, 0xe1, 0x3f, 0x0c, 0xc8, 0xb6, 0x63, 0x0c, 0xa6 }
        };

        private readonly static byte[][] ExpectedRoundKeys192 = new byte[13][]
        {
            new byte[] { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5 },
            new byte[] { 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b, 0xfe, 0x0c, 0x91, 0xf7, 0x24, 0x02, 0xf5, 0xa5 },
            new byte[] { 0xec, 0x12, 0x06, 0x8e, 0x6c, 0x82, 0x7f, 0x6b, 0x0e, 0x7a, 0x95, 0xb9, 0x5c, 0x56, 0xfe, 0xc2 },
            new byte[] { 0x4d, 0xb7, 0xb4, 0xbd, 0x69, 0xb5, 0x41, 0x18, 0x85, 0xa7, 0x47, 0x96, 0xe9, 0x25, 0x38, 0xfd },
            new byte[] { 0xe7, 0x5f, 0xad, 0x44, 0xbb, 0x09, 0x53, 0x86, 0x48, 0x5a, 0xf0, 0x57, 0x21, 0xef, 0xb1, 0x4f },
            new byte[] { 0xa4, 0x48, 0xf6, 0xd9, 0x4d, 0x6d, 0xce, 0x24, 0xaa, 0x32, 0x63, 0x60, 0x11, 0x3b, 0x30, 0xe6 },
            new byte[] { 0xa2, 0x5e, 0x7e, 0xd5, 0x83, 0xb1, 0xcf, 0x9a, 0x27, 0xf9, 0x39, 0x43, 0x6a, 0x94, 0xf7, 0x67 },
            new byte[] { 0xc0, 0xa6, 0x94, 0x07, 0xd1, 0x9d, 0xa4, 0xe1, 0xec, 0x17, 0x86, 0xeb, 0x6f, 0xa6, 0x49, 0x71 },
            new byte[] { 0x48, 0x5f, 0x70, 0x32, 0x22, 0xcb, 0x87, 0x55, 0xe2, 0x6d, 0x13, 0x52, 0x33, 0xf0, 0xb7, 0xb3 },
            new byte[] { 0x40, 0xbe, 0xeb, 0x28, 0x2f, 0x18, 0xa2, 0x59, 0x67, 0x47, 0xd2, 0x6b, 0x45, 0x8c, 0x55, 0x3e },
            new byte[] { 0xa7, 0xe1, 0x46, 0x6c, 0x94, 0x11, 0xf1, 0xdf, 0x82, 0x1f, 0x75, 0x0a, 0xad, 0x07, 0xd7, 0x53 },
            new byte[] { 0xca, 0x40, 0x05, 0x38, 0x8f, 0xcc, 0x50, 0x06, 0x28, 0x2d, 0x16, 0x6a, 0xbc, 0x3c, 0xe7, 0xb5 },
            new byte[] { 0xe9, 0x8b, 0xa0, 0x6f, 0x44, 0x8c, 0x77, 0x3c, 0x8e, 0xcc, 0x72, 0x04, 0x01, 0x00, 0x22, 0x02 }
        };

        private readonly static byte[][] ExpectedRoundKeys256 = new byte[15][]
        {
            new byte[] { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81 },
            new byte[] { 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 },
            new byte[] { 0x9b, 0xa3, 0x54, 0x11, 0x8e, 0x69, 0x25, 0xaf, 0xa5, 0x1a, 0x8b, 0x5f, 0x20, 0x67, 0xfc, 0xde },
            new byte[] { 0xa8, 0xb0, 0x9c, 0x1a, 0x93, 0xd1, 0x94, 0xcd, 0xbe, 0x49, 0x84, 0x6e, 0xb7, 0x5d, 0x5b, 0x9a },
            new byte[] { 0xd5, 0x9a, 0xec, 0xb8, 0x5b, 0xf3, 0xc9, 0x17, 0xfe, 0xe9, 0x42, 0x48, 0xde, 0x8e, 0xbe, 0x96 },
            new byte[] { 0xb5, 0xa9, 0x32, 0x8a, 0x26, 0x78, 0xa6, 0x47, 0x98, 0x31, 0x22, 0x29, 0x2f, 0x6c, 0x79, 0xb3 },
            new byte[] { 0x81, 0x2c, 0x81, 0xad, 0xda, 0xdf, 0x48, 0xba, 0x24, 0x36, 0x0a, 0xf2, 0xfa, 0xb8, 0xb4, 0x64 },
            new byte[] { 0x98, 0xc5, 0xbf, 0xc9, 0xbe, 0xbd, 0x19, 0x8e, 0x26, 0x8c, 0x3b, 0xa7, 0x09, 0xe0, 0x42, 0x14 },
            new byte[] { 0x68, 0x00, 0x7b, 0xac, 0xb2, 0xdf, 0x33, 0x16, 0x96, 0xe9, 0x39, 0xe4, 0x6c, 0x51, 0x8d, 0x80 },
            new byte[] { 0xc8, 0x14, 0xe2, 0x04, 0x76, 0xa9, 0xfb, 0x8a, 0x50, 0x25, 0xc0, 0x2d, 0x59, 0xc5, 0x82, 0x39 },
            new byte[] { 0xde, 0x13, 0x69, 0x67, 0x6c, 0xcc, 0x5a, 0x71, 0xfa, 0x25, 0x63, 0x95, 0x96, 0x74, 0xee, 0x15 },
            new byte[] { 0x58, 0x86, 0xca, 0x5d, 0x2e, 0x2f, 0x31, 0xd7, 0x7e, 0x0a, 0xf1, 0xfa, 0x27, 0xcf, 0x73, 0xc3 },
            new byte[] { 0x74, 0x9c, 0x47, 0xab, 0x18, 0x50, 0x1d, 0xda, 0xe2, 0x75, 0x7e, 0x4f, 0x74, 0x01, 0x90, 0x5a },
            new byte[] { 0xca, 0xfa, 0xaa, 0xe3, 0xe4, 0xd5, 0x9b, 0x34, 0x9a, 0xdf, 0x6a, 0xce, 0xbd, 0x10, 0x19, 0x0d },
            new byte[] { 0xfe, 0x48, 0x90, 0xd1, 0xe6, 0x18, 0x8d, 0x0b, 0x04, 0x6d, 0xf3, 0x44, 0x70, 0x6c, 0x63, 0x1e }
        };

        public static IEnumerable<(byte[] Key, AesKeySize KeySize, byte[][] ExpectedRoundKeys)> RoundKeyExpand
        {
            get
            {
                byte[] key = new byte[] { 0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c };
                yield return (key, AesKeySize.Aes128, ExpectedRoundKeys128);

                key = new byte[] { 0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b };
                yield return (key, AesKeySize.Aes192, ExpectedRoundKeys192);

                key = new byte[] { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
                yield return (key, AesKeySize.Aes256, ExpectedRoundKeys256);
            }
        }

        #endregion
    }
}
