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
        public ICryptoTransform CreateOfbEncryptor(string key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128)
            => CreateOfbEncryptor(key.GetKey(keySize), IV, keySize);

        public ICryptoTransform CreateOfbEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128)
            => CreateEncryptor(key, IV, EncryptModeEnum.OFB, keySize);

        private ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, EncryptModeEnum encryptMode, AesKeySize keySize = AesKeySize.Aes128)
        {
            if (EncryptModeEnum.OFB.Equals(encryptMode))
                return AesOFBEncryptor.CreateEncryptor(key, IV, keySize);

            throw new Exception($"Encryption Mode {encryptMode} not valid");
        }

        private class AesOFBEncryptor : ICryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private AesOFBEncryptor(Aes aes)
            {
                this.Aes = aes;
            }

            #region Encryptor/Decryptor

            public static ICryptoTransform CreateEncryptor(byte[] key, byte[] IV, AesKeySize keySize = AesKeySize.Aes128)
            {
                Aes aes = new Aes(key.Copy(), IV.Copy(), keySize);
                aes.EncryptMode = EncryptModeEnum.OFB;
                aes.InitializeRoundKey();
                return new AesOFBEncryptor(aes);
            }

            #endregion

            #region ICryptoTransform

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;
                byte[] oBuffer = new byte[OutputBlockSize];
                byte[] iBuffer = new byte[inputCount];

                Array.Copy(inputBuffer, inputOffset, iBuffer, 0, inputCount);
                Array.Copy(this.Aes.IV, 0, oBuffer, 0, OutputBlockSize);

                for (int i = 0; i < inputCount; i += OutputBlockSize)
                {
                    // Encrypt IV and Xor with plain then move to outputBuffer
                    this.Aes.Encrypt(oBuffer, 0, oBuffer, 0);
                    Array.Copy(iBuffer.Xor(oBuffer, InputBlockSize), 0, outputBuffer, outputOffset + i, OutputBlockSize);

                    iBuffer.ShiftLeft(InputBlockSize * 8);
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
                    Array.Copy(this.Aes.IV, 0, oBuffer, 0, OutputBlockSize);

                    // Encrypt IV and Xor with plain
                    this.Aes.Encrypt(oBuffer, 0, oBuffer, 0);
                    Array.Copy(iBuffer.Xor(oBuffer, InputBlockSize), 0, output, 0, inputCount);

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
