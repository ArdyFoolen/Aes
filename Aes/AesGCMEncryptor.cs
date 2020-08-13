using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;

namespace Aes.AF
{
    public partial class Aes
    {
        public IAuthenticatedCryptoTransform CreateEncryptor(byte[] key, byte[] IV, string additionalData, AesKeySize keySize = AesKeySize.Aes128)
        {
            byte[] newIV = new byte[IV.Length];
            Array.Copy(IV, 0, newIV, 0, IV.Length);

            Aes aes = new Aes(key, newIV, keySize);
            aes.PaddingMode = PaddingMode.None;
            aes.EncryptMode = EncryptModeEnum.GCM;
            aes.InitializeRoundKey();

            return new AesGCMEncryptor(aes, additionalData);
        }

        public IAuthenticatedCryptoTransform CreateEncryptor(byte[] key, byte[] IV, byte[] additionalData, AesKeySize keySize = AesKeySize.Aes128)
        {
            byte[] newIV = new byte[IV.Length];
            Array.Copy(IV, 0, newIV, 0, IV.Length);

            Aes aes = new Aes(key, newIV, keySize);
            aes.PaddingMode = PaddingMode.None;
            aes.EncryptMode = EncryptModeEnum.GCM;
            aes.InitializeRoundKey();

            return new AesGCMEncryptor(aes, additionalData);
        }

        private class AesGCMEncryptor : IAuthenticatedCryptoTransform, IDisposable
        {
            private Aes Aes { get; }
            private byte[] AdditionalData { get; }

            private byte[] H { get; set; }
            private byte[] InitialCounter { get; set; }
            private byte[] Counter { get; set; }
            private byte[] ByteTag { get; set; }
            private int LengthCipher { get; set; }

            public AesGCMEncryptor(Aes aes, string additionalData)
            {
                this.Aes = aes;
                this.AdditionalData = ConvertAdditionalDataToByteArray(additionalData);

                Initialize();
            }

            public AesGCMEncryptor(Aes aes, byte[] additionalData)
            {
                this.Aes = aes;
                this.AdditionalData = additionalData;

                Initialize();
            }

            private void Initialize()
            {
                CreateHashKey();
                CreateInitialCounter();
                CreateCounter();
                CreateByteTagWithAAD();
            }

            /// <summary>
            /// 1:		X0 = 0
            /// 2:		For i = 1; i <= m; i++
            ///		        Xi = (Xi-1 XOR Ai) * H
            /// </summary>
            private void CreateByteTagWithAAD()
            {
                ByteTag = new byte[OutputBlockSize];
                int blocks = (AdditionalData.Length % 16) == 0 ? AdditionalData.Length / 16 : AdditionalData.Length / 16 + 1;
                byte[][] x = new byte[blocks + 1][];
                x[0] = new byte[OutputBlockSize];

                for (int i = 1; i <= blocks; i++)
                {
                    byte[] aadBlock = new byte[OutputBlockSize];
                    int length = AdditionalData.Length - ((i - 1) * 16) > 16 ? 16 : AdditionalData.Length - ((i - 1) * 16);
                    Array.Copy(AdditionalData, (i - 1) * 16, aadBlock, 0, length);
                    x[i] = GaloisMultiplication.GMul128(GaloisMultiplication.Add(x[i - 1], aadBlock), H);
                }

                Array.Copy(x[x.Length - 1], 0, ByteTag, 0, OutputBlockSize);
            }

            /// <summary>
            /// Create multitude of 16 byte blocks for AAD
            /// </summary>
            /// <param name="additionalData"></param>
            /// <returns></returns>
            private byte[] ConvertAdditionalDataToByteArray(string additionalData)
            {
                byte[] aad = Encoding.ASCII.GetBytes(additionalData);
                byte[] result = new byte[(additionalData.Length % 16) == 0 ? additionalData.Length : (additionalData.Length / 16) * 16 + 1];
                Array.Copy(aad, 0, result, 0, aad.Length);
                return result;
            }

            private void CreateCounter()
            {
                Counter = new byte[OutputBlockSize];
                Array.Copy(InitialCounter, 0, Counter, 0, Counter.Length);
            }

            /// <summary>
            /// 2:		If length(IV) == 96
            ///             Y0 = IV || 0(31)1
            ///     	Else
            ///             Y0 = GHASH(H, {}, IV)
            /// </summary>
            /// <returns></returns>
            private void CreateInitialCounter()
            {
                InitialCounter = new byte[OutputBlockSize];
                if (this.Aes.IV.Length == 12)
                {
                    this.Aes.IV.CopyTo(InitialCounter, 0);
                    InitialCounter[InitialCounter.Length - 1] = 0x01;
                }
                else
                    InitialCounter = GHashIV(H, this.Aes.IV);
            }

            /// <summary>
            /// 3:		For i = 1; i <= n; i++
            ///             Xi = (Xi-1 XOR IV) * H
            /// 4:		T = (Xn XOR (0 || length(IV))) * H            
            /// </summary>
            /// <param name="H"></param>
            /// <param name="IV"></param>
            /// <returns></returns>
            private byte[] GHashIV(byte[] H, byte[] IV)
            {
                int blocks = IV.Length / 16;
                blocks += IV.Length % 16 == 0 ? 1 : 2;
                byte[][] x = new byte[blocks][];
                x[0] = new byte[OutputBlockSize];

                for (int i = 1; i < blocks; i++)
                {
                    byte[] IVBlock = new byte[OutputBlockSize];
                    int cpLength = IV.Length - ((i - 1) * 16);
                    cpLength = cpLength > 16 ? 16 : cpLength;
                    Array.Copy(IV, (i - 1) * 16, IVBlock, 0, cpLength);
                    x[i] = GaloisMultiplication.GMul128(GaloisMultiplication.Add(x[i - 1], IVBlock), H);
                }

                return GaloisMultiplication.GMul128(GaloisMultiplication.Add(x[x.Length - 1], ConvertToByteArray(IV.Length * 8)), H);
            }

            private byte[] ConvertToByteArray(int length)
            {
                byte[] result = new byte[OutputBlockSize];
                byte[] lArray = BitConverter.GetBytes(length);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(lArray);
                Array.Copy(lArray, 0, result, result.Length - lArray.Length, lArray.Length);

                return result;
            }

            private byte[] ConvertToByteArray(int aadLength, int cipherLength)
            {
                byte[] result = new byte[OutputBlockSize];
                byte[] lArray = BitConverter.GetBytes(cipherLength);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(lArray);
                Array.Copy(lArray, 0, result, result.Length - lArray.Length, lArray.Length);

                lArray = BitConverter.GetBytes(aadLength);
                if (BitConverter.IsLittleEndian)
                    Array.Reverse(lArray);
                Array.Copy(lArray, 0, result, 8 - lArray.Length, lArray.Length);

                return result;
            }

            /// <summary>
            /// 1:		H = E(K, 0)
            /// </summary>
            /// <returns></returns>
            private void CreateHashKey()
            {
                H = new byte[OutputBlockSize];
                byte[] zeros = new byte[InputBlockSize];
                this.Aes.Encrypt(zeros, 0, H, 0);
            }

            private void IncrementCounter()
            {
                int index = Counter.Length - 1;
                do
                {
                    Counter[index] += 1;
                } while (index >= 0 && Counter[index--] == 0);
            }


            private void SetTag()
            {
                Tag = BitConverter.ToString(ByteTag).Replace("-", string.Empty);
            }

            #region IAuthenticatedCryptoTransform

            public string Tag { get; private set; }

            #endregion

            #region ICryptoTransform

            public int TransformBlock(byte[] inputBuffer, int inputOffset, int inputCount, byte[] outputBuffer, int outputOffset)
            {
                int returnCount = inputCount;
                this.LengthCipher += inputCount;

                for (int i = 0; i < inputCount; i += OutputBlockSize)
                {
                    IncrementCounter();

                    byte[] iBuffer = new byte[InputBlockSize];
                    byte[] oBuffer = new byte[OutputBlockSize];

                    Array.Copy(inputBuffer, inputOffset + i, iBuffer, 0, InputBlockSize);
                    this.Aes.Encrypt(Counter, 0, oBuffer, 0);
                    oBuffer = this.Aes.AddRoundKey(iBuffer, oBuffer);
                    ByteTag = GaloisMultiplication.GMul128(GaloisMultiplication.Add(oBuffer, ByteTag), H);

                    Array.Copy(oBuffer, 0, outputBuffer, outputOffset + i, OutputBlockSize);
                }

                return returnCount;
            }

            public byte[] TransformFinalBlock(byte[] inputBuffer, int inputOffset, int inputCount)
            {
                this.LengthCipher += inputCount;

                byte[] output = new byte[inputCount];

                byte[] oBuffer = new byte[OutputBlockSize];

                if (inputCount > 0)
                {
                    IncrementCounter();

                    byte[] iBuffer = new byte[InputBlockSize];

                    Array.Copy(inputBuffer, inputOffset, iBuffer, 0, InputBlockSize);
                    this.Aes.Encrypt(Counter, 0, oBuffer, 0);
                    oBuffer = this.Aes.AddRoundKey(iBuffer, oBuffer);

                    Array.Clear(oBuffer, inputCount, oBuffer.Length - inputCount);
                    ByteTag = GaloisMultiplication.GMul128(GaloisMultiplication.Add(oBuffer, ByteTag), H);

                    Array.Copy(oBuffer, 0, output, 0, inputCount);
                }

                byte[] length = ConvertToByteArray(AdditionalData.Length * 8, LengthCipher * 8);
                ByteTag = GaloisMultiplication.GMul128(GaloisMultiplication.Add(ByteTag, length), H);
                this.Aes.Encrypt(InitialCounter, 0, oBuffer, 0);
                ByteTag = GaloisMultiplication.Add(oBuffer, ByteTag);
                SetTag();

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
