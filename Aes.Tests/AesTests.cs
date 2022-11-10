using Aes.AF;
using NUnit.Framework;
using System;
using System.CodeDom;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes.Tests
{
    [TestFixture]
    public class AesTests
    {
        [TestCaseSource(typeof(AesSourceHelper), "RoundKeyExpand")]
        public void RoundKey_Expanded_Correct((byte[] Key, AesKeySize KeySize, byte[][] ExpectedRoundKeys) values)
        {
            // Arrange
            AesManagerContext aesManager = new AesManagerContext(values.Key, values.KeySize);

            // Act
            aesManager.InitializeKey();

            // Assert
            Assert.AreEqual(values.ExpectedRoundKeys.Length, aesManager.RoundKeyLength);
            for (int r = 0; r < values.ExpectedRoundKeys.Length; r++)
                Assert.That(values.ExpectedRoundKeys[r].Select((b, i) => new { value = b, index = i }).All(a => aesManager.GetRoundKey(r)[a.index] == a.value));
        }

        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecrypt")]
        public void EnDecrypt_EachStep_ShouldBeCorrect((byte[] In, byte[] Out, Action<Aes.AF.AesManager, Stream, Stream> Crypt) values)
        {
            AesManagerContext aesManager = new AesManagerContext();
            using (Stream inStream = new MemoryStream())
            {
                // Arrange
                inStream.Write(values.In, 0, 16);
                inStream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream outStream = new MemoryStream();
                values.Crypt(aesManager, outStream, inStream);

                // Assert
                outStream.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[17];
                int bytesRead = outStream.Read(actual, 0, 17);

                Assert.AreEqual(16, bytesRead);
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
            }
        }

        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecryptDifferentPadding")]
        public void EnDecrypt_DifferentPadding_ShouldBeCorrect((byte[] In, byte[] Out, Action<Aes.AF.AesManager, Stream, Stream> Crypt) values)
        {
            indexR = 0;
            PaddingFactory.DiRandomByte = () => GetRandomByte();
            AesManagerContext aesManager = new AesManagerContext();
            using (Stream inStream = new MemoryStream())
            {
                // Arrange
                inStream.Write(values.In, 0, values.In.Length);
                inStream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream outStream = new MemoryStream();
                values.Crypt(aesManager, outStream, inStream);

                // Assert
                outStream.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[values.Out.Length + 1];
                int bytesRead = outStream.Read(actual, 0, values.Out.Length + 1);

                Assert.AreEqual(values.Out.Length, bytesRead);
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
            }
        }

        // TestVectors: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CFB.pdf
        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecryptCFB")]
        public void EnDecryptCFB_EachStep_ShouldBeCorrect((byte[] In, byte[] Out, Action<Aes.AF.AesManager, Stream, Stream> Crypt) values)
        {
            AesManagerContext aesManager = new AesManagerContext();
            using (Stream inStream = new MemoryStream())
            {
                // Arrange
                inStream.Write(values.In, 0, values.In.Length);
                inStream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream outStream = new MemoryStream();
                values.Crypt(aesManager, outStream, inStream);

                // Assert
                outStream.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[values.Out.Length + 1];
                int bytesRead = outStream.Read(actual, 0, values.Out.Length + 1);

                Assert.AreEqual(values.Out.Length, bytesRead);

                var result = string.Join("", values.Out.Select((b, i) => $"{b:x2}{actual[i]:x2}\r\n"));
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
            }
        }

        // TestVectors: https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_OFB.pdf
        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecryptOFB")]
        public void EnDecryptOFB_EachStep_ShouldBeCorrect((byte[] In, byte[] Out, Action<Aes.AF.AesManager, Stream, Stream> Crypt) values)
        {
            AesManagerContext aesManager = new AesManagerContext();
            using (Stream inStream = new MemoryStream())
            {
                // Arrange
                inStream.Write(values.In, 0, values.In.Length);
                inStream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream outStream = new MemoryStream();
                values.Crypt(aesManager, outStream, inStream);

                // Assert
                outStream.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[values.Out.Length + 1];
                int bytesRead = outStream.Read(actual, 0, values.Out.Length + 1);

                Assert.AreEqual(values.Out.Length, bytesRead);

                var result = string.Join("", values.Out.Select((b, i) => $"{b:x2}{actual[i]:x2}\r\n"));
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
            }
        }

        byte[] randoms = new byte[] { 0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0xa7, 0xb8, 0xc9, 0xda, 0xeb, 0xfc, 0xad, 0xbe, 0xcf, 0xd0 };
        int indexR = 0;

        private byte GetRandomByte()
            => randoms[indexR++];
    }
}
