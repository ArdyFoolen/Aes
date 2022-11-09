using Aes.AF.Extensions;
using Aes.AF;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes.Tests
{
    public class ExtensionTests
    {
        [Test]
        public void ToEnum_EncryptModeEnum_Success()
        {
            // Act
            var mode = "CFB".ToEnum<EncryptModeEnum>();

            // Assert
            Assert.That(mode, Is.EqualTo(EncryptModeEnum.CFB));
        }

        [Test]
        public void ToEnum_FeedbackSizeEnum_Success()
        {
            // Act
            var mode = "1".ToEnum<FeedbackSizeEnum>();

            // Assert
            Assert.That(mode, Is.EqualTo(FeedbackSizeEnum.One));
        }
    }
}
