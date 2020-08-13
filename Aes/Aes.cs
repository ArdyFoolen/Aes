using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
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


// Galois Counter Mode
// https://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
// https://stackoverflow.com/questions/10655026/gcm-multiplication-implementation
// http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf   with TestVectors
// https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-spec.pdf With Examples at the end to verify implementation
// https://books.google.bg/books?id=VaiYIZHduXQC&pg=PA303&lpg=PA303&dq=ghash+input+and+output&source=bl&ots=GXUyzEcIXH&sig=ACfU3U1XsSY_WiPK9CUUoUktc_oPNQhg0g&hl=en&sa=X&ved=2ahUKEwjPqLvZnZ_qAhWjzYUKHSOyBxsQ6AEwDHoECAgQAQ#v=onepage&q=ghash%20input%20and%20output&f=false

namespace Aes.AF
{
    public enum AesKeySize
    {
        Aes128 = 128,
        Aes192 = 192,
        Aes256 = 256
    };

    public enum EncryptModeEnum
    {
        ECB,
        CBC,
        CTR,
        GCM
    };

    public partial class Aes
    {
        #region Fields

        public AesKeySize KeySize { get; protected set; }
        protected string Key { get; set; }
        protected byte[] ByteKey { get; set; }
        protected byte[][] RoundKey;
        protected byte[] IV { get; set; } = null;

        #endregion

        #region ctors

        public Aes() { }

        protected Aes(byte[] byteKey, AesKeySize keySize = AesKeySize.Aes128)
        {
            this.KeySize = keySize;
            int kSz = GetKeySize();
            if (kSz != byteKey.Length)
                throw new ArgumentException($"Key length not equal {kSz}");
            ByteKey = byteKey;
        }

        protected Aes(byte[] byteKey, byte[] IV, AesKeySize keySize = AesKeySize.Aes128)
        {
            this.KeySize = keySize;
            int kSz = GetKeySize();
            if (kSz != byteKey.Length)
                throw new ArgumentException($"Key length not equal {kSz}");

            ByteKey = byteKey;
            this.IV = IV;
        }

        #endregion

        #region ExpandRoundKey

        protected void InitializeRoundKey()
        {
            RoundKey = CtorRoundKey();
            ExpandRoundKey();
        }

        protected void ExpandRoundKey()
        {
            RoundKey[0] = ByteKey;
            for (int round = 0; round < NumberOfKeyExpands(); round++)
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
            Action nextIndex = () =>
            {
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
            Action nextIndex = () =>
            {
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
            int dwordNbr = GetNumberOfColumns() - 1;
            byte[] rKey = circularByteLeftOfDword(dwordNbr, prevRoundKey);
            rKey = substituteByteOfDword(dwordNbr, rKey);
            rKey = addRoundConstant(round, dwordNbr, rKey);

            for (int todword = 0; todword <= dwordNbr; todword++)
            {
                int frmdword = todword - 1;
                if (frmdword < 0)
                    frmdword = dwordNbr;

                for (int i = 0; i < 4; i++)
                    if ((int)KeySize > 192 && (frmdword % 8) == 3)
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

        public PaddingMode PaddingMode { get; private set; }

        public EncryptModeEnum EncryptMode { get; private set; } = EncryptModeEnum.ECB;

        /// <summary>
        /// Padding function gets called NumberOfBytes times
        /// First int, NumberOfBytes to pad
        /// Second int, CurrentByte being pad
        /// Return byte, the pad byte
        /// </summary>
        private Func<int, int, byte> PaddingFunction { get; set; } = null;

        /// <summary>
        /// Remove padding function called ones
        /// First byte[], is the last buffer decrypted
        /// Second int, buffer length
        /// Return int, number of padded bytes to be removed from the buffer
        /// </summary>
        private Func<byte[], int, int> RemovePaddingFunction { get; set; } = null;

        private int GetKeySize()
            => AesKeySize.Aes128.Equals(KeySize) ?
                    16 :
            AesKeySize.Aes192.Equals(KeySize) ?
                    24 :
                    32;

        private int NumberOfKeyExpands()
            => AesKeySize.Aes128.Equals(KeySize) ?
                    10 :
            AesKeySize.Aes192.Equals(KeySize) ?
                    8 :
                    7;

        private int NumberOfRounds()
            => AesKeySize.Aes128.Equals(KeySize) ?
                    10 :
            AesKeySize.Aes192.Equals(KeySize) ?
                    12 :
                    14;
        private int GetNumberOfColumns()
            => AesKeySize.Aes128.Equals(KeySize) ?
                    4 :
            AesKeySize.Aes192.Equals(KeySize) ?
                    6 :
                    8;

        protected byte[][] CtorRoundKey()
            => new byte[NumberOfRounds() + 1][];

        private int InputBlockSize
        {
            get { return 16; }
        }

        private int OutputBlockSize
        {
            get { return 16; }
        }

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
                    output[row + 4 * column] = MixColumnFormulas.Get[row](column, input);

            return output;
        }

        private byte[] InverseMixColumns(byte[] input)
        {
            byte[] output = new byte[input.Length];

            for (int row = 0; row < 4; row++)
                //for (int column = 0; column < GetNumberOfColumns(KeySize); column++)
                for (int column = 0; column < 4; column++)
                    output[row + 4 * column] = MixColumnFormulas.Inverse[row](column, input);

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

        private void Encrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            byte[] buffer = new byte[InputBlockSize];
            Array.Copy(inputBuffer, inputOffset, buffer, 0, InputBlockSize);
            buffer = AddRoundKey(buffer, RoundKey[0]);
            for (int round = 1; round < NumberOfRounds(); round++)
                buffer = EncryptRound(buffer, RoundKey[round]);
            buffer = FinalEncrypt(buffer, RoundKey[NumberOfRounds()]);
            Array.Copy(buffer, 0, outputBuffer, outputOffset, OutputBlockSize);
        }

        #endregion

        #region Decrypt

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

        private void Decrypt(byte[] inputBuffer, int inputOffset, byte[] outputBuffer, int outputOffset)
        {
            byte[] buffer = new byte[InputBlockSize];
            Array.Copy(inputBuffer, inputOffset, buffer, 0, InputBlockSize);

            buffer = AddRoundKey(buffer, RoundKey[NumberOfRounds()]);
            for (int round = NumberOfRounds() - 1; round > 0; round--)
                buffer = DecryptRound(buffer, RoundKey[round]);
            buffer = FinalDecrypt(buffer, RoundKey[0]);

            Array.Copy(buffer, 0, outputBuffer, outputOffset, OutputBlockSize);
        }

        #endregion
    }
}
