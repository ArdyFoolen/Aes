﻿using Aes.AF.Extensions;
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
        public ICryptoTransform CreateCbcDecryptor(string key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            => CreateDecryptor(key.GetKey(keySize), IV, EncryptModeEnum.CBC, keySize, paddingMode);

        public ICryptoTransform CreateCbcDecryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            => CreateDecryptor(key, IV, EncryptModeEnum.CBC, keySize, paddingMode);

        public ICryptoTransform CreateCtrDecryptor(string key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            => CreateCtrDecryptor(key.GetKey(keySize), IV, keySize, paddingMode);

        public ICryptoTransform CreateCtrDecryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            => CreateDecryptor(key, IV, EncryptModeEnum.CTR, keySize, paddingMode);

        private ICryptoTransform CreateDecryptor(byte[] key, byte[] IV, EncryptModeEnum encryptMode, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
        {
            if (EncryptModeEnum.CBC.Equals(encryptMode))
                return AesCBCDecryptor.CreateDecryptor(key, IV, keySize, paddingMode);
            if (EncryptModeEnum.CTR.Equals(encryptMode))
                return AesCTREncryptor.CreateEncryptor(key, IV, keySize);

            throw new Exception($"Encryption Mode {encryptMode} not valid");
        }

        private class AesCBCDecryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private AesCBCDecryptor(Aes aes)
            {
                this.Aes = aes;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateDecryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128, PaddingMode paddingMode = PaddingMode.PKCS7)
            {
                Aes aes = new Aes(key.Copy(), IV.Copy(), keySize);
                aes.PaddingMode = paddingMode;
                aes.RemovePaddingFunction = PaddingFactory.GetRemovePaddingFunction(paddingMode);
                aes.EncryptMode = EncryptModeEnum.CBC;
                aes.InitializeRoundKey();
                return new AesCBCDecryptor(aes);
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
