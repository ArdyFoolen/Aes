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
        public ICryptoTransform CreateDecryptor(byte[] key, AesKeySize keySize)
        {
            Aes aes = new Aes(key, keySize);
            aes.RemovePaddingFunction = this.RemovePaddingFunction;
            return new AesDecryptor(aes);
        }

        private class AesDecryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            public AesDecryptor(Aes aes)
            {
                this.Aes = aes;
            }

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
                        this.Aes.Decrypt(inputBuffer, inputOffset + i, lastBuffer, 0);
                    else
                        this.Aes.Decrypt(inputBuffer, inputOffset + i, outputBuffer, outputOffset);

                    outputOffset += OutputBlockSize;
                }

                if (isFirstTransfer)
                {
                    Array.Copy(outputBuffer, outputBuffer.Length - OutputBlockSize, lastBuffer, 0, OutputBlockSize);
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
