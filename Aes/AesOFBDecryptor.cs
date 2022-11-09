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
        public ICryptoTransform CreateOfbDecryptor(string key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateDecryptor(key.GetKey(keySize), IV, EncryptModeEnum.OFB, keySize, feedbackSize);

        public ICryptoTransform CreateOfbDecryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateDecryptor(key, IV, EncryptModeEnum.OFB, keySize, feedbackSize);

        private class AesOFBDecryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private FeedbackSizeEnum FeedbackSize { get; }
            private AesOFBDecryptor(Aes aes, FeedbackSizeEnum feedbackSize)
            {
                this.Aes = aes;
                FeedbackSize = feedbackSize;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateDecryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            {
                Aes aes = new Aes(key.Copy(), IV.Copy(), keySize);
                aes.EncryptMode = EncryptModeEnum.OFB;
                aes.InitializeRoundKey();
                return new AesOFBDecryptor(aes, feedbackSize);
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

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;

                if (isFirstTransfer)
                {
                    lastBuffer = new byte[OutputBlockSize];
                    returnCount -= OutputBlockSize;
                }
                else
                {
                    Array.Copy(lastBuffer, 0, outputBuffer, 0, OutputBlockSize);
                    outputOffset += OutputBlockSize;
                }

                for (int i = 0; i < inputCount; i += OutputBlockSize)
                {
                    if (outputOffset >= outputBuffer.Length)
                    {
                        this.Aes.Decrypt(inputBuffer, inputOffset + i, lastBuffer, 0);
                        byte[] buffer = new byte[OutputBlockSize];
                        Array.Copy(lastBuffer, 0, buffer, 0, OutputBlockSize);
                        lastBuffer = buffer.Add(this.Aes.IV);
                    }
                    else
                    {
                        this.Aes.Decrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset);
                        byte[] buffer = new byte[OutputBlockSize];
                        Array.Copy(outputBuffer, outputOffset, buffer, 0, OutputBlockSize);
                        buffer = buffer.Add(this.Aes.IV);
                        Array.Copy(buffer, 0, outputBuffer, outputOffset, OutputBlockSize);
                    }
                    Array.Copy(inputBuffer, inputOffset + i, this.Aes.IV, 0, OutputBlockSize);

                    outputOffset += OutputBlockSize;
                }

                if (isFirstTransfer)
                {
                    Array.Copy(outputBuffer, outputOffset - OutputBlockSize, lastBuffer, 0, OutputBlockSize);
                    isFirstTransfer = false;
                }

                return returnCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (this.Aes.RemovePaddingFunction == null)
                    return lastBuffer;

                int padding = OutputBlockSize - this.Aes.RemovePaddingFunction(lastBuffer, OutputBlockSize);
                byte[] output = new byte[padding];
                Array.Copy(lastBuffer, 0, output, 0, padding);
                ResetTransfer();
                return output;
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
