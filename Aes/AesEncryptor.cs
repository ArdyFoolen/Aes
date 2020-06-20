using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

namespace Aes.AF
{
    public partial class Aes
    {
        public ICryptoTransform CreateEncryptor(byte[] key, AesKeySize keySize)
        {
            Aes aes = new Aes(key, keySize);
            aes.PaddingFunction = this.PaddingFunction;
            return new AesEncryptor(aes);
        }

        private class AesEncryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            public AesEncryptor(Aes aes)
            {
                this.Aes = aes;
            }

            #region ICryptoTransform

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;

                for (int i = 0; i < inputCount; i += OutputBlockSize)
                    this.Aes.Encrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset + i);

                return returnCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (this.Aes.PaddingFunction != null)
                    for (int i = inputCount; i < InputBlockSize; i++)
                        inputBuffer[i] = this.Aes.PaddingFunction(InputBlockSize - inputCount, i - inputCount);

                if (this.Aes.PaddingFunction != null && inputCount > 0)
                {
                    byte[] buffer = new byte[OutputBlockSize];
                    this.Aes.Encrypt(inputBuffer, inputOffset, buffer, 0);
                    return buffer;
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
