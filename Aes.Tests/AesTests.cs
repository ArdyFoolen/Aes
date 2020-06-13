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
            using (Stream stream = new MemoryStream())
            using (AesContext aes = new AesContext(stream, values.Key, values.KeySize))
            {
                // Assert
                Assert.AreEqual(values.ExpectedRoundKeys.Length, aes.RoundKeyLength);
                for (int r = 0; r < values.ExpectedRoundKeys.Length; r++)
                    Assert.That(values.ExpectedRoundKeys[r].Select((b, i) => new { value = b, index = i }).All(a => aes.GetRoundKey(r)[a.index] == a.value));
            }
        }

        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecrypt")]
        public void EnDecrypt_EachStep_ShouldBeCorrect((AesKeySize KeySize, byte[] Key, byte[] In, byte[] Out, Action<Aes.AF.Aes, Stream> Crypt) values)
        {
            using (Stream stream = new MemoryStream())
            using (AesContext aes = new AesContext(stream, values.Key, values.KeySize))
            {
                // Arrange
                stream.Write(values.In, 0, 16);
                stream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream writer = new MemoryStream();
                values.Crypt(aes, writer);

                // Assert
                writer.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[17];
                int bytesRead = writer.Read(actual, 0, 17);

                Assert.AreEqual(16, bytesRead);
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
            }
        }
    }
}
