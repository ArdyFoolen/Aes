using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

// See link https://www.comparitech.com/blog/information-security/what-is-aes-encryption/
// https://www.tutorialspoint.com/cryptography/advanced_encryption_standard.htm
// https://kavaliro.com/wp-content/uploads/2014/03/AES.pdf
// https://www.lri.fr/~fmartignon/documenti/systemesecurite/5-AES.pdf
// https://crypto.stackexchange.com/questions/20/what-are-the-practical-differences-between-256-bit-192-bit-and-128-bit-aes-enc/1527#1527
// https://csrc.nist.gov/csrc/media/publications/fips/197/final/documents/fips-197.pdf
// https://en.wikipedia.org/wiki/AES_key_schedule#:~:text=AES%20uses%20a%20key%20schedule,keys%20from%20the%20initial%20key.
// http://www.angelfire.com/biz7/atleast/mix_columns.pdf
// https://en.wikipedia.org/wiki/Rijndael_MixColumns
// https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf With Examples at the end to verify implementation
namespace Aes.AF
{
    public enum AesKeySize
    {
        Aes128 = 128,
        Aes192 = 196,
        Aes256 = 256
    };

    public class Aes : Stream, IDisposable
    {
        #region Fields

        protected Stream Inner;
        public AesKeySize KeySize { get; protected set; }
        protected string Key { get; set; }
        protected byte[] ByteKey { get; set; }
        protected byte[][] RoundKey;

        #endregion

        #region ctors

        public Aes(Stream inner, string key, AesKeySize keySize = AesKeySize.Aes128)
        {
            this.Inner = inner;
            this.KeySize = keySize;
            SetKey(key);
            ByteKey = Encoding.ASCII.GetBytes(this.Key);
            RoundKey = CtorRoundKey(keySize);
            ExpandRoundKey();
        }

        public Aes(Stream inner, byte[] byteKey, AesKeySize keySize = AesKeySize.Aes128)
        {
            this.Inner = inner;
            this.KeySize = keySize;
            int kSz = GetKeySize(KeySize);
            if (kSz != byteKey.Length)
                throw new ArgumentException($"Key length not equal {kSz}");
            ByteKey = byteKey;
            RoundKey = CtorRoundKey(keySize);
            ExpandRoundKey();
        }

        #endregion

        protected void SetKey(string key)
        {
            int kSz = GetKeySize(KeySize);
            string keyFmt = string.Format("{{0, -{0}}}", kSz);
            if (kSz < key.Length)
                this.Key = string.Format(keyFmt, key.Substring(0, kSz));
            else
                this.Key = string.Format(keyFmt, key);
        }

        #region ExpandRoundKey

        protected void ExpandRoundKey()
        {
            RoundKey[0] = ByteKey;
            for (int round = 0; round < NumberOfKeyExpands(KeySize); round++)
                RoundKey[round + 1] = KeyScedule(round, RoundKey[round]);

            if ((int)KeySize > 128)
                ReArrangeRoundKeys();
        }

        private void ReArrangeRoundKeys()
        {
            if (AesKeySize.Aes192.Equals(KeySize))
                ReArrangeRoundKeys192();
            else if (AesKeySize.Aes256.Equals(KeySize))
                ReArrangeRoundKeys256();
        }

        private void ReArrangeRoundKeys192()
        {
            byte[] roundKey = new byte[16];

            RoundKey[12] = new byte[16];
            Array.Copy(RoundKey[8], 0, RoundKey[12], 0, 16);

            int sourceIndex = 16;
            int from = 7;
            Action nextIndex = () => {
                sourceIndex -= 8;
                if (sourceIndex < 0)
                    sourceIndex = 16;
                if (sourceIndex == 16)
                    from -= 1;
            };
            for (int r = 11; r >= 0; r--)
            {
                Array.Copy(RoundKey[from], sourceIndex, roundKey, 8, 8);
                nextIndex();
                Array.Copy(RoundKey[from], sourceIndex, roundKey, 0, 8);
                nextIndex();
                RoundKey[r] = new byte[16];
                Array.Copy(roundKey, RoundKey[r], roundKey.Length);
            }
        }

        private void ReArrangeRoundKeys256()
        {
            byte[] roundKey = new byte[16];

            int sourceIndex = 0;
            int from = 7;
            Action nextIndex = () => {
                sourceIndex -= 16;
                if (sourceIndex < 0)
                    sourceIndex = 16;
                if (sourceIndex == 16)
                    from -= 1;
            };
            for (int r = 14; r >= 0; r--)
            {
                Array.Copy(RoundKey[from], sourceIndex, roundKey, 0, 16);
                nextIndex();
                RoundKey[r] = new byte[16];
                Array.Copy(roundKey, RoundKey[r], roundKey.Length);
            }
        }

        private byte[] KeyScedule(int round, byte[] prevRoundKey)
        {
            int dwordNbr = GetNumberOfColumns(KeySize) - 1;
            byte[] rKey = circularByteLeftOfDword(dwordNbr, prevRoundKey);
            rKey = substituteByteOfDword(dwordNbr, rKey);
            rKey = addRoundConstant(round, dwordNbr, rKey);

            for (int todword = 0; todword <= dwordNbr; todword++)
            {
                int frmdword = todword - 1;
                if (frmdword < 0)
                    frmdword = dwordNbr;

                for (int i = 0; i < 4; i++)
                    if ((int)KeySize > 196 && (frmdword % 8) == 3)
                        rKey[todword * 4 + i] = (byte)(substituteByte(rKey[frmdword * 4 + i]) ^ prevRoundKey[todword * 4 + i]);
                    else
                        rKey[todword * 4 + i] = (byte)(rKey[frmdword * 4 + i] ^ prevRoundKey[todword * 4 + i]);
            }

            return rKey;
        }

        private byte[] addRoundConstant(int round, int dword, byte[] bKey)
        {
            byte[] rKey = new byte[bKey.Length];
            Array.Copy(bKey, rKey, bKey.Length);
            int startIndex = dword * 4;
            rKey[startIndex] = (byte)(bKey[startIndex] ^ RoundConstants.Get[round]);
            return rKey;
        }

        /// <summary>
        /// Rotate the bytes of a dword left
        /// </summary>
        /// <param name="dword">
        /// Zero based index into bKey of the dWord to be rotated, dword = 4 bytes
        /// </param>
        /// <param name="bKey"></param>
        private byte[] circularByteLeftOfDword(int dword, byte[] bKey)
        {
            byte[] rKey = new byte[bKey.Length];
            Array.Copy(bKey, rKey, bKey.Length);
            int startIndex = dword * 4;
            byte first = bKey[startIndex];
            for (int i = 0; i < 3; i++)
                rKey[startIndex + i] = bKey[startIndex + i + 1];
            rKey[startIndex + 3] = first;
            return rKey;
        }

        #endregion

        #region Properties

        private int GetKeySize(AesKeySize keySize)
            => AesKeySize.Aes128.Equals(keySize) ?
                    16 :
            AesKeySize.Aes192.Equals(keySize) ?
                    24 :
                    32;

        private int NumberOfKeyExpands(AesKeySize keySize)
            => AesKeySize.Aes128.Equals(keySize) ?
                    10 :
            AesKeySize.Aes192.Equals(keySize) ?
                    8 :
                    7;

        private int NumberOfRounds(AesKeySize keySize)
            => AesKeySize.Aes128.Equals(keySize) ?
                    10 :
            AesKeySize.Aes192.Equals(keySize) ?
                    12 :
                    14;
        private int GetNumberOfColumns(AesKeySize keySize)
            => AesKeySize.Aes128.Equals(keySize) ?
                    4 :
            AesKeySize.Aes192.Equals(keySize) ?
                    6 :
                    8;

        protected byte[][] CtorRoundKey(AesKeySize keySize)
            => new byte[NumberOfRounds(keySize) + 1][];

        #endregion

        #region AddRoundKey

        protected virtual byte[] AddRoundKey(byte[] input, byte[] key)
        {
            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                output[i] = (byte)(input[i] ^ key[i]);
            return output;
        }

        #endregion

        #region Byte(Inverse)Substitution

        private byte substituteByte(byte from)
            => SBox.Get[from];

        private byte inverseSubstituteByte(byte from)
            => SBox.Inverse[from];

        /// <summary>
        /// Substitute byte from a dword according S-Box
        /// </summary>
        /// <param name="dword">
        /// Zero based index into bKey of the dWord to be substituted, dword = 4 bytes
        /// </param>
        /// <param name="bKey"></param>
        private byte[] substituteByteOfDword(int dword, byte[] bKey)
        {
            byte[] rKey = new byte[bKey.Length];
            Array.Copy(bKey, rKey, bKey.Length);
            int startIndex = dword * 4;
            for (int i = 0; i < 4; i++)
                rKey[startIndex + i] = substituteByte(bKey[startIndex + i]);
            return rKey;
        }

        protected virtual byte[] ByteSubstitution(byte[] input)
        {
            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                output[i] = substituteByte(input[i]);
            return output;
        }


        private byte[] ByteInverseSubstitution(byte[] input)
        {
            byte[] output = new byte[input.Length];
            for (int i = 0; i < input.Length; i++)
                output[i] = inverseSubstituteByte(input[i]);
            return output;
        }

        #endregion

        #region (Inverse)ShiftRows

        protected virtual byte[] ShiftRows(byte[] input)
        {
            byte[] output = new byte[input.Length];

            for (int row = 0; row < 4; row++)
                //for (int column = 0; column < GetNumberOfColumns(KeySize); column++)
                for (int column = 0; column < 4; column++)
                    if (column - row < 0)
                        //output[row + 4 * (column - row + GetNumberOfColumns(KeySize))] = input[row + 4 * column];
                        output[row + 4 * (column - row + 4)] = input[row + 4 * column];
                    else
                        output[row + 4 * (column - row)] = input[row + 4 * column];

            return output;
        }

        private byte[] InverseShiftRows(byte[] input)
        {
            byte[] output = new byte[input.Length];

            for (int row = 0; row < 4; row++)
                //for (int column = 0; column < GetNumberOfColumns(KeySize); column++)
                for (int column = 0; column < 4; column++)
                    //if (column + row >= GetNumberOfColumns(KeySize))
                    //output[row + 4 * (column + row - GetNumberOfColumns(KeySize))] = input[row + 4 * column];
                    if (column + row >= 4)
                        output[row + 4 * (column + row - 4)] = input[row + 4 * column];
                    else
                        output[row + 4 * (column + row)] = input[row + 4 * column];

            return output;
        }

        #endregion

        #region (Inverse)MixColumns

        protected virtual byte[] MixColumns(byte[] input)
        {
            byte[] output = new byte[input.Length];

            for (int row = 0; row < 4; row++)
                //for (int column = 0; column < GetNumberOfColumns(KeySize); column++)
                for (int column = 0; column < 4; column++)
                    output[row + 4 * column] = MixColumnFormulas.Get[row](column, input, GMul);

            return output;
        }

        private byte[] InverseMixColumns(byte[] input)
        {
            byte[] output = new byte[input.Length];

            for (int row = 0; row < 4; row++)
                //for (int column = 0; column < GetNumberOfColumns(KeySize); column++)
                for (int column = 0; column < 4; column++)
                    output[row + 4 * column] = MixColumnFormulas.Inverse[row](column, input, GMul);

            return output;
        }

        #endregion

        #region Encrypt

        private byte[] FinalEncrypt(byte[] input, byte[] key)
        {
            byte[] output = new byte[input.Length];
            output = ByteSubstitution(input);
            output = ShiftRows(output);
            output = AddRoundKey(output, key);
            return output;
        }

        protected virtual byte[] EncryptRound(byte[] input, byte[] key)
        {
            byte[] output = new byte[input.Length];
            output = ByteSubstitution(input);
            output = ShiftRows(output);
            output = MixColumns(output);
            output = AddRoundKey(output, key);
            return output;
        }

        public void Encrypt(Stream writer)
        {
            int bytesRead;
            //int blockLength = GetKeySize(KeySize);
            int blockLength = 16;
            byte[] buffer = new byte[blockLength];

            do
            {
                bytesRead = this.Inner.Read(buffer, 0, blockLength);
                //if (bytesRead < blockLength)
                //    for (int i = bytesRead; i < blockLength; i++)
                //        buffer[i] = 0xFF;

                if (bytesRead > 0)
                {
                    buffer = AddRoundKey(buffer, RoundKey[0]);
                    for (int round = 1; round < NumberOfRounds(KeySize); round++)
                        buffer = EncryptRound(buffer, RoundKey[round]);
                    buffer = FinalEncrypt(buffer, RoundKey[NumberOfRounds(KeySize)]);

                    writer.Write(buffer, 0, blockLength);
                }
            } while (bytesRead == blockLength);
        }

        #endregion

        #region Decrypt

        private byte[] BeginDecrypt(byte[] input, byte[] key)
        {
            byte[] output = new byte[input.Length];
            output = AddRoundKey(input, key);
            return output;
        }

        private byte[] FinalDecrypt(byte[] input, byte[] key)
        {
            byte[] output = new byte[input.Length];
            output = InverseShiftRows(input);
            output = ByteInverseSubstitution(output);
            output = AddRoundKey(output, key);
            return output;
        }

        private byte[] DecryptRound(byte[] input, byte[] key)
        {
            byte[] output = new byte[input.Length];
            output = InverseShiftRows(input);
            output = ByteInverseSubstitution(output);
            output = AddRoundKey(output, key);
            output = InverseMixColumns(output);
            return output;
        }

        public void Decrypt(Stream writer)
        {
            int bytesRead;
            //int blockLength = GetKeySize(KeySize);
            int blockLength = 16;
            byte[] buffer = new byte[blockLength];

            do
            {
                bytesRead = this.Inner.Read(buffer, 0, blockLength);
                if (bytesRead > 0)
                {
                    buffer = BeginDecrypt(buffer, RoundKey[NumberOfRounds(KeySize)]);
                    for (int round = NumberOfRounds(KeySize) - 1; round > 0; round--)
                        buffer = DecryptRound(buffer, RoundKey[round]);
                    buffer = FinalDecrypt(buffer, RoundKey[0]);

                    //bytesRead = blockLength - 1;
                    //while (bytesRead >= 0 && buffer[bytesRead] == 0xff)
                    //    bytesRead--;
                    writer.Write(buffer, 0, bytesRead);
                }
            } while (bytesRead > 0);
        }

        #endregion

        #region Galois Field (256) Multiplication of two Bytes

        // TestVectors
        // Before       After
        // db 13 53 45  8e 4d a1 bc
        // f2 0a 22 5c  9f dc 58 9d
        // 01 01 01 01  01 01 01 01
        // c6 c6 c6 c6  c6 c6 c6 c6
        // d4 d4 d4 d5  d5 d5 d7 d6
        // 2d 26 31 4c  4d 7e bd f8

        /// <summary>
        /// Galois Field (256) Multiplication of two Bytes
        /// </summary>
        /// <param name="a"></param>
        /// <param name="b"></param>
        /// <returns></returns>
        private byte GMul(byte a, byte b)
        {
            byte p = 0;

            for (int counter = 0; counter < 8; counter++)
            {
                if ((b & 1) != 0)
                    p ^= a;

                bool isHighBitSet = (a & 0x80) != 0;
                a <<= 1;

                if (isHighBitSet)
                    a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */

                b >>= 1;
            }

            return p;
        }

        #endregion

        #region Stream Implementation

        public override bool CanRead => this.Inner.CanRead;

        public override bool CanSeek => this.Inner.CanSeek;

        public override bool CanWrite => this.Inner.CanWrite;

        public override long Length => this.Inner.Length;

        public override long Position { get => this.Inner.Position; set => this.Inner.Position = value; }

        public override void Flush()
        {
            this.Inner.Flush();
        }

        public override int Read(byte[] buffer, int offset, int count)
        {
            return this.Inner.Read(buffer, offset, count);
        }

        public override long Seek(long offset, SeekOrigin origin)
        {
            return this.Inner.Seek(offset, origin);
        }

        public override void SetLength(long value)
        {
            this.Inner.SetLength(value);
        }

        public override void Write(byte[] buffer, int offset, int count)
        {
            this.Inner.Write(buffer, offset, count);
        }

        #endregion

        #region IDisposable

        // To detect redundant calls
        private bool _disposed = false;

        // Instantiate a SafeHandle instance.
        private SafeHandle _safeHandle = new SafeFileHandle(IntPtr.Zero, true);

        // Public implementation of Dispose pattern callable by consumers.
        public new void Dispose() => Dispose(true);

        // Protected implementation of Dispose pattern.
        protected override void Dispose(bool disposing)
        {
            if (_disposed)
            {
                return;
            }

            if (disposing)
            {
                this.Inner.Dispose();
                // Dispose managed state (managed objects).
                _safeHandle?.Dispose();
            }

            _disposed = true;
        }

        #endregion
    }
}
