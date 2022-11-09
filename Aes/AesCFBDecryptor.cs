using Aes.AF.Extensions;
using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF
{
    public partial class AesManager
    {
        public ICryptoTransform CreateCfbDecryptor(string key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateDecryptor(key.GetKey(keySize), IV, EncryptModeEnum.CFB, keySize, feedbackSize);

        public ICryptoTransform CreateCfbDecryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateDecryptor(key, IV, EncryptModeEnum.CFB, keySize, feedbackSize);

        private ICryptoTransform CreateDecryptor(byte[] key, byte[] IV, EncryptModeEnum encryptMode, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
        {
            if (EncryptModeEnum.CFB.Equals(encryptMode))
                return AesCFBDecryptor.CreateDecryptor(key, IV, keySize, feedbackSize);
            if (EncryptModeEnum.OFB.Equals(encryptMode))
                return AesOFBEncryptor.CreateEncryptor(key, IV, keySize, feedbackSize);

            throw new Exception($"Encryption Mode {encryptMode} not valid");
        }

        private class AesCFBDecryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private int FeedbackSize { get; }
            private AesCFBDecryptor(Aes aes, FeedbackSizeEnum feedbackSize)
            {
                this.Aes = aes;
                FeedbackSize = (int)feedbackSize;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateDecryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            {
                Aes aes = new Aes(key.Copy(), IV.Copy(), keySize);
                aes.EncryptMode = EncryptModeEnum.CFB;
                aes.InitializeRoundKey();
                return new AesCFBDecryptor(aes, feedbackSize);
            }

            #endregion

            #region ICryptoTransform

            byte[] lastBuffer = null;
            bool isFirstTransfer = true;
            private void ResetTransfer()
            {
                lastBuffer = null;
                isFirstTransfer = true;
            }

            //public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            //{
            //    int returnCount = inputCount;

            //    for (int i = 0; i < inputCount; i += OutputBlockSize)
            //    {
            //        byte[] oBuffer = new byte[OutputBlockSize];
            //        byte[] iBuffer = new byte[InputBlockSize];
            //        Array.Copy(inputBuffer, inputOffset + i, iBuffer, 0, InputBlockSize);
            //        for (int f = 0; f < OutputBlockSize; f += FeedbackSize / 8)
            //        {
            //            this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
            //            oBuffer = iBuffer.Add(oBuffer);
            //            Array.Copy(oBuffer, 0, outputBuffer, outputOffset + i + f, FeedbackSize / 8);

            //            this.Aes.IV.ShiftLeft(FeedbackSize);
            //            iBuffer.ShiftRight(128 - FeedbackSize);
            //            this.Aes.IV = this.Aes.IV.Add(iBuffer);

            //            Array.Copy(inputBuffer, inputOffset + i + f + 1, iBuffer, 0, InputBlockSize);
            //        }
            //    }

            //    return returnCount;
            //}
            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;

                if (FeedbackSize == 1)
                {
                    for (int i = 0; i < inputCount; i += OutputBlockSize)
                    {
                        byte[] oBuffer = new byte[OutputBlockSize];
                        byte[] iBuffer = new byte[InputBlockSize];
                        Array.Copy(inputBuffer, inputOffset + i, iBuffer, 0, InputBlockSize);
                        for (int f = 0; f < OutputBlockSize; f++)
                        {
                            byte[] oBufferFeedback1 = new byte[1];
                            for (int b = 0; b < 8; b++)
                            {
                                this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                                oBuffer = iBuffer.Add(oBuffer);
                                byte temp = (byte)(oBuffer[0] & 0x80);
                                temp >>= b;
                                oBufferFeedback1[0] |= temp;

                                this.Aes.IV.ShiftLeft(FeedbackSize);
                                iBuffer.ShiftRight(128 - FeedbackSize);
                                this.Aes.IV = this.Aes.IV.Add(iBuffer);

                                Array.Copy(inputBuffer, inputOffset + i + f, iBuffer, 0, InputBlockSize - i - f);
                            }
                            Array.Copy(oBufferFeedback1, 0, outputBuffer, outputOffset + i + f, 1);
                            iBuffer.ShiftLeft(FeedbackSize);
                        }
                    }
                }
                else
                {
                    for (int i = 0; i < inputCount; i += OutputBlockSize)
                    {
                        byte[] oBuffer = new byte[OutputBlockSize];
                        byte[] iBuffer = new byte[InputBlockSize];
                        Array.Copy(inputBuffer, inputOffset + i, iBuffer, 0, InputBlockSize);
                        for (int f = 0; f < OutputBlockSize; f += FeedbackSize / 8)
                        {
                            this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                            oBuffer = iBuffer.Add(oBuffer);
                            Array.Copy(oBuffer, 0, outputBuffer, outputOffset + i + f, FeedbackSize / 8);

                            this.Aes.IV.ShiftLeft(FeedbackSize);
                            iBuffer.ShiftRight(128 - FeedbackSize);
                            this.Aes.IV = this.Aes.IV.Add(iBuffer);

                            int length = inputBuffer.Length - (inputOffset + i + f + 1);
                            length = length > InputBlockSize ? InputBlockSize : length;
                            Array.Copy(inputBuffer, inputOffset + i + f + 1, iBuffer, 0, length);
                        }
                    }
                }

                return returnCount;
            }

            //public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            //{
            //    if (inputCount > 0)
            //    {
            //        byte[] iBuffer = new byte[InputBlockSize];
            //        byte[] oBuffer = new byte[OutputBlockSize];
            //        Array.Copy(inputBuffer, inputOffset, iBuffer, 0, InputBlockSize);
            //        byte[] output = new byte[inputCount];

            //        for (int f = 0; f < inputCount; f += FeedbackSize / 8)
            //        {
            //            this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
            //            oBuffer = iBuffer.Add(oBuffer);
            //            Array.Copy(oBuffer, 0, output, f, FeedbackSize / 8);

            //            this.Aes.IV.ShiftLeft(FeedbackSize);
            //            iBuffer.ShiftRight(128 - FeedbackSize);
            //            this.Aes.IV = this.Aes.IV.Add(iBuffer);

            //            Array.Copy(inputBuffer, inputOffset + f + 1, iBuffer, 0, InputBlockSize);
            //        }

            //        return output;
            //    }
            //    else
            //        return new byte[0];
            //}
            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (inputCount > 0)
                {
                    byte[] iBuffer = new byte[InputBlockSize];
                    byte[] oBuffer = new byte[OutputBlockSize];
                    Array.Copy(inputBuffer, inputOffset, iBuffer, 0, InputBlockSize);
                    byte[] output = new byte[inputCount];

                    if (FeedbackSize == 1)
                    {
                        for (int f = 0; f < inputCount; f++)
                        {
                            byte[] oBufferFeedback1 = new byte[1];
                            for (int b = 0; b < 8; b++)
                            {
                                this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                                oBuffer = iBuffer.Add(oBuffer);
                                byte temp = (byte)(oBuffer[0] & 0x80);
                                temp >>= b;
                                oBufferFeedback1[0] |= temp;

                                this.Aes.IV.ShiftLeft(FeedbackSize);
                                iBuffer.ShiftRight(128 - FeedbackSize);
                                this.Aes.IV = this.Aes.IV.Add(iBuffer);

                                int length = inputBuffer.Length - (inputOffset + f);
                                length = length > InputBlockSize ? InputBlockSize : length;
                                Array.Copy(inputBuffer, inputOffset + f, iBuffer, 0, length);
                                iBuffer.ShiftLeft(b + 1);
                            }
                            Array.Copy(oBufferFeedback1, 0, output, f, 1);
                        }
                    }
                    else
                    {
                        for (int f = 0; f < inputCount; f += FeedbackSize / 8)
                        {
                            this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                            oBuffer = iBuffer.Add(oBuffer);
                            Array.Copy(oBuffer, 0, output, f, FeedbackSize / 8);

                            this.Aes.IV.ShiftLeft(FeedbackSize);
                            iBuffer.ShiftRight(128 - FeedbackSize);
                            this.Aes.IV = this.Aes.IV.Add(iBuffer);

                            Array.Copy(inputBuffer, inputOffset + f + 1, iBuffer, 0, InputBlockSize - f - 1);
                        }
                    }

                    return output;
                }
                else
                    return new byte[0];
            }

            public bool CanReuseTransform
            {
                get { return true; }
            }

            public bool CanTransformMultipleBlocks
            {
                get { return true; }
            }

            public int InputBlockSize
            {
                get { return 16; }
            }

            public int OutputBlockSize
            {
                get { return 16; }
            }

            #endregion

            #region IDisposable

            // To detect redundant calls
            private bool _disposed = false;

            // Instantiate a SafeHandle instance.
            private SafeHandle _safeHandle = new SafeFileHandle(IntPtr.Zero, true);

            // Public implementation of Dispose pattern callable by consumers.
            public void Dispose() => Dispose(true);

            // Protected implementation of Dispose pattern.
            protected void Dispose(bool disposing)
            {
                if (_disposed)
                {
                    return;
                }

                if (disposing)
                {
                    // Dispose managed state (managed objects).
                    _safeHandle?.Dispose();
                }

                _disposed = true;
            }

            #endregion

        }
    }
}
