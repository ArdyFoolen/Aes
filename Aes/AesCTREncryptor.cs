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
        private class AesCTREncryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private int Counter { get; set; } = 0;
            private AesCTREncryptor(Aes aes)
            {
                this.Aes = aes;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128)
            {
                if (IV.Length != 12)
                    throw new ArgumentException($"IV length not equal {12}");

                byte[] newIV = new byte[16];
                Array.Copy(IV, 0, newIV, 0, IV.Length);

                Aes aes = new Aes(key, newIV, keySize);
                aes.PaddingMode = PaddingMode.None;
                aes.EncryptMode = EncryptModeEnum.CTR;
                aes.InitializeRoundKey();
                return new AesCTREncryptor(aes);
            }

            #endregion

            private void IncrementCounter()
            {
                Counter++;
                byte[] counter = BitConverter.GetBytes(Counter);
                Array.Copy(counter, 0, this.Aes.IV, 12, 4);
            }

            #region ICryptoTransform

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;

                for (int i = 0; i < inputCount; i += OutputBlockSize)
                {
                    byte[] iBuffer = new byte[InputBlockSize];
                    byte[] oBuffer = new byte[OutputBlockSize];

                    Array.Copy(inputBuffer, inputOffset + i, iBuffer, 0, InputBlockSize);
                    this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                    oBuffer = this.Aes.AddRoundKey(iBuffer, oBuffer);

                    IncrementCounter();

                    Array.Copy(oBuffer, 0, outputBuffer, outputOffset + i, OutputBlockSize);
                }

                return returnCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                if (inputCount > 0)
                {
                    byte[] iBuffer = new byte[InputBlockSize];
                    byte[] oBuffer = new byte[OutputBlockSize];

                    Array.Copy(inputBuffer, inputOffset, iBuffer, 0, InputBlockSize);
                    this.Aes.Encrypt(this.Aes.IV, 0, oBuffer, 0);
                    oBuffer = this.Aes.AddRoundKey(iBuffer, oBuffer);

                    byte[] output = new byte[inputCount];
                    Array.Copy(oBuffer, 0, output, 0, inputCount);

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
