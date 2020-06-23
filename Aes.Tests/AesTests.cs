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
            AesContext aes = new AesContext(values.Key, values.KeySize);

            // Act
            aes.InitializeKey();

            // Assert
            Assert.AreEqual(values.ExpectedRoundKeys.Length, aes.RoundKeyLength);
            for (int r = 0; r < values.ExpectedRoundKeys.Length; r++)
                Assert.That(values.ExpectedRoundKeys[r].Select((b, i) => new { value = b, index = i }).All(a => aes.GetRoundKey(r)[a.index] == a.value));
        }

        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecrypt")]
        public void EnDecrypt_EachStep_ShouldBeCorrect((byte[] In, byte[] Out, Action<Aes.AF.Aes, Stream, Stream> Crypt) values)
        {
            AesContext aes = new AesContext();
            using (Stream inStream = new MemoryStream())
            {
                // Arrange
                inStream.Write(values.In, 0, 16);
                inStream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream outStream = new MemoryStream();
                values.Crypt(aes, outStream, inStream);

                // Assert
                outStream.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[17];
                int bytesRead = outStream.Read(actual, 0, 17);

                Assert.AreEqual(16, bytesRead);
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
            }
        }

        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecryptDifferentPadding")]
        public void EnDecrypt_DifferentPadding_ShouldBeCorrect((byte[] In, byte[] Out, Action<Aes.AF.Aes, Stream, Stream> Crypt) values)
        {
            AesContext aes = new AesContext();
            using (Stream inStream = new MemoryStream())
            {
                // Arrange
                inStream.Write(values.In, 0, values.In.Length);
                inStream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream outStream = new MemoryStream();
                values.Crypt(aes, outStream, inStream);

                // Assert
                outStream.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[values.Out.Length + 1];
                int bytesRead = outStream.Read(actual, 0, values.Out.Length + 1);

                Assert.AreEqual(values.Out.Length, bytesRead);
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
            }
        }
    }
}
