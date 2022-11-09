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
        public ICryptoTransform CreateOfbEncryptor(string key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateOfbEncryptor(key.GetKey(keySize), IV, keySize, feedbackSize);

        public ICryptoTransform CreateOfbEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            => CreateEncryptor(key, IV, EncryptModeEnum.CFB, keySize, feedbackSize);

        private class AesOFBEncryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private FeedbackSizeEnum FeedbackSize { get; }
            private AesOFBEncryptor(Aes aes, FeedbackSizeEnum feedbackSize)
            {
                this.Aes = aes;
                this.FeedbackSize = feedbackSize;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, FeedbackSizeEnum feedbackSize = FeedbackSizeEnum.OneHundredTwentyEight)
            {
                Aes aes = new Aes(key.Copy(), IV.Copy(), keySize);
                aes.EncryptMode = EncryptModeEnum.OFB;
                aes.InitializeRoundKey();
                return new AesOFBEncryptor(aes, feedbackSize);
            }

            #endregion

            #region ICryptoTransform

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;

                for (int i = 0; i < inputCount; i += OutputBlockSize)
                {
                    byte[] buffer = new byte[InputBlockSize];
                    Array.Copy(inputBuffer, inputOffset + i, buffer, 0, InputBlockSize);
                    buffer = buffer.Add(this.Aes.IV);
                    this.Aes.Encrypt(buffer, 0, outputBuffer, outputOffset + i);
                    Array.Copy(outputBuffer, outputOffset + i, this.Aes.IV, 0, InputBlockSize);
                }

                return returnCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                byte[] buffer = new byte[InputBlockSize];
                byte[] output = new byte[OutputBlockSize];
                Array.Copy(inputBuffer, inputOffset, buffer, 0, InputBlockSize);
                buffer = buffer.Add(this.Aes.IV);
                this.Aes.Encrypt(buffer, 0, output, 0);
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
