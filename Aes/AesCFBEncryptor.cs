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
        public ICryptoTransform CreateCfbEncryptor(string key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateCfbEncryptor(key.GetKey(keySize), IV, keySize, feedbackSize);

        public ICryptoTransform CreateCfbEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateEncryptor(key, IV, EncryptModeEnum.CFB, keySize, feedbackSize);

        private ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, EncryptModeEnum encryptMode, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
        {
            if (EncryptModeEnum.CFB.Equals(encryptMode))
                return AesCFBEncryptor.CreateEncryptor(key, IV, keySize, feedbackSize);

            throw new Exception($"Encryption Mode {encryptMode} not valid");
        }

        private class AesCFBEncryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private int FeedbackSize { get; }
            private AesCFBEncryptor(Aes aes, FeedbackSizeEnum feedbackSize)
            {
                this.Aes = aes;
                FeedbackSize = (int)feedbackSize;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            {
                Aes aes = new Aes(key.Copy(), IV.Copy(), keySize);
                aes.EncryptMode = EncryptModeEnum.CFB;
                aes.InitializeRoundKey();
                return new AesCFBEncryptor(aes, feedbackSize);
            }

            #endregion

            #region ICryptoTransform

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;
                byte[] oBuffer = new byte[OutputBlockSize];
                byte[] iBuffer = new byte[inputCount];

                Array.Copy(inputBuffer, inputOffset, iBuffer, 0, inputCount);

                for (int i = 0; i < inputCount * 8; i += FeedbackSize)
                {
                    // Encrypt IV and Xor with plain
                    this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                    oBuffer = iBuffer.Xor(oBuffer, InputBlockSize);

                    // Move cipher to outputBuffer
                    if (FeedbackSize == 1)
                    {
                        byte temp = (byte)(oBuffer[0] & 0x80);
                        temp >>= i % 8;
                        outputBuffer[outputOffset + i / 8] |= temp;
                    }
                    else
                    {
                        Array.Copy(oBuffer, 0, outputBuffer, outputOffset + i / 8, FeedbackSize / 8);
                    }

                    // Shift cipher into IV
                    this.Aes.IV.ShiftLeft(FeedbackSize);
                    oBuffer.ShiftRight(128 - FeedbackSize);
                    this.Aes.IV = this.Aes.IV.Xor(oBuffer, InputBlockSize);

                    iBuffer.ShiftLeft(FeedbackSize);
                }

                return returnCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (inputCount > 0)
                {
                    byte[] output = new byte[inputCount];
                    byte[] oBuffer = new byte[OutputBlockSize];
                    byte[] iBuffer = new byte[inputCount];

                    Array.Copy(inputBuffer, inputOffset, iBuffer, 0, inputCount);

                    for (int i = 0; i < inputCount * 8; i += FeedbackSize)
                    {
                        // Encrypt IV and Xor with plain
                        this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                        oBuffer = iBuffer.Add(oBuffer);

                        // Move cipher to outputBuffer
                        if (FeedbackSize == 1)
                        {
                            byte temp = (byte)(oBuffer[0] & 0x80);
                            temp >>= i % 8;
                            output[i / 8] |= temp;
                        }
                        else
                        {
                            var count = FeedbackSize / 8;
                            count = inputCount - i / 8 > count ? count : inputCount - i / 8;
                            Array.Copy(oBuffer, 0, output, i / 8, count);
                        }

                        // Shift cipher into IV
                        this.Aes.IV.ShiftLeft(FeedbackSize);
                        oBuffer.ShiftRight(128 - FeedbackSize);
                        this.Aes.IV = this.Aes.IV.Xor(oBuffer, InputBlockSize);

                        iBuffer.ShiftLeft(FeedbackSize);
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
