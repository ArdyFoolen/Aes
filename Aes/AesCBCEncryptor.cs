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
        public ICryptoTransform CreateCbcEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            => CreateEncryptor(key, IV, EncryptModeEnum.CBC, keySize, paddingMode);

        public ICryptoTransform CreateCtrEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            => CreateEncryptor(key, IV, EncryptModeEnum.CTR, keySize, paddingMode);

        private ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, EncryptModeEnum encryptMode, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (EncryptModeEnum.CBC.Equals(encryptMode))
                return AesCBCEncryptor.CreateEncryptor(key, IV, keySize, paddingMode);
            if (EncryptModeEnum.CTR.Equals(encryptMode))
                return AesCTREncryptor.CreateEncryptor(key, IV, keySize);

            throw new Exception($"Encryption Mode {encryptMode} not valid");
        }

        private class AesCBCEncryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private AesCBCEncryptor(Aes aes)
            {
                this.Aes = aes;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            {
                Aes aes = new Aes(key, IV, keySize);
                aes.PaddingMode = paddingMode;
                aes.PaddingFunction = PaddingFactory.GetPaddingFunction(paddingMode);
                aes.EncryptMode = EncryptModeEnum.CBC;
                aes.InitializeRoundKey();
                return new AesCBCEncryptor(aes);
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
                if (this.Aes.PaddingFunction != null)
                    for (int i = inputCount; i < InputBlockSize; i++)
                        inputBuffer[i] = this.Aes.PaddingFunction(InputBlockSize - inputCount, i - inputCount);

                if (this.Aes.PaddingFunction != null)
                {
                    byte[] buffer = new byte[InputBlockSize];
                    byte[] output = new byte[OutputBlockSize];
                    Array.Copy(inputBuffer, inputOffset, buffer, 0, InputBlockSize);
                    buffer = buffer.Add(this.Aes.IV);
                    this.Aes.Encrypt(buffer, 0, output, 0);
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
