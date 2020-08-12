using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes.Tests
{
    [TestFixture]
    public class AesGCMTests
    {
        [TestCaseSource(typeof(AesSourceHelper), "EncryptDecryptGCM")]
        public void EnDecrypt_Tag_ShouldBeCorrect((byte[] In, byte[] Out, string ExpectedTag, Func<Aes.AF.Aes, Stream, Stream, string> Crypt) values)
        {
            AesContext aes = new AesContext();
            using (Stream inStream = new MemoryStream())
            {
                // Arrange
                inStream.Write(values.In, 0, values.In.Length);
                inStream.Seek(0, SeekOrigin.Begin);

                // Act
                Stream outStream = new MemoryStream();
                string actualTag = values.Crypt(aes, outStream, inStream);

                // Assert
                outStream.Seek(0, SeekOrigin.Begin);
                byte[] actual = new byte[17];
                int bytesRead = outStream.Read(actual, 0, 17);

                Assert.AreEqual(values.In.Length, bytesRead);
                Assert.That(values.Out.Select((b, i) => new { value = b, index = i }).All(a => actual[a.index] == a.value));
                Assert.AreEqual(values.ExpectedTag, actualTag);
            }
        }
    }
}
