﻿using Aes.AF;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes.Tests
{
    [TestFixture]
    public class GaloisMultiplicationTests
    {
        #region Squaring Finit Field size times

        [TestCase(new object[] { 0x01 })]
        [TestCase(new object[] { 0x10 })]
        [TestCase(new object[] { 0x08 })]
        [TestCase(new object[] { 0x80 })]
        [TestCase(new object[] { 0x03 })]
        [TestCase(new object[] { 0x30 })]
        [TestCase(new object[] { 0x0c })]
        [TestCase(new object[] { 0xc0 })]
        [TestCase(new object[] { 0x11 })]
        [TestCase(new object[] { 0x88 })]
        [TestCase(new object[] { 0x33 })]
        [TestCase(new object[] { 0xcc })]
        [TestCase(new object[] { 0x00 })]
        [TestCase(new object[] { 0xff })]
        public void GMul_SquaringFinitFieldSize_ShouldHaveStartResult(byte value)
        {
            // Arrange
            byte r = value;

            // Act
            for (int i = 0; i < 8; i++)
                r = GaloisMultiplication.GMul(r, r);

            // Assert
            Assert.AreEqual(value, r);
        }

        [TestCase(new object[] { new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } })]
        [TestCase(new object[] { new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } })]
        [TestCase(new object[] { new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 } })]
        [TestCase(new object[] { new byte[] { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 } })]
        [TestCase(new object[] { new byte[] { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 } })]
        [TestCase(new object[] { new byte[] { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 } })]
        [TestCase(new object[] { new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 } })]
        [TestCase(new object[] { new byte[] { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 } })]
        [TestCase(new object[] { new byte[] { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c } })]
        [TestCase(new object[] { new byte[] { 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0 } })]
        [TestCase(new object[] { new byte[] { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } })]
        [TestCase(new object[] { new byte[] { 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 } })]
        [TestCase(new object[] { new byte[] { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 } })]
        [TestCase(new object[] { new byte[] { 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc } })]
        [TestCase(new object[] { new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f } })]
        [TestCase(new object[] { new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 } })]
        [TestCase(new object[] { new byte[] { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 } })]
        [TestCase(new object[] { new byte[] { 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 } })]
        [TestCase(new object[] { new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } })]
        [TestCase(new object[] { new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 } })]
        public void GMul128_SquaringFinitFieldSize_ShouldHaveStartResult(byte[] value)
        {
            // Arrange
            byte[] r = value;

            // Act
            for (int i = 0; i < 128; i++)
                r = GaloisMultiplication.GMul128(r, r);

            // Assert
            Assert.IsTrue(value.Select((s, i) => new { value = s, index = i }).All(a => a.value == r[a.index]));
        }

        #endregion

        #region Commutative

        /// <summary>
        /// Commutative: val1 * val2 = val2 * val1
        /// </summary>
        /// <param name="value"></param>
        [TestCase(new object[] { 0x01, 0x10 })]
        [TestCase(new object[] { 0x10, 0x01 })]
        [TestCase(new object[] { 0x08, 0x80 })]
        [TestCase(new object[] { 0x80, 0x08 })]
        [TestCase(new object[] { 0x03, 0x30 })]
        [TestCase(new object[] { 0x30, 0x03 })]
        [TestCase(new object[] { 0x0c, 0xc0 })]
        [TestCase(new object[] { 0xc0, 0x0c })]
        [TestCase(new object[] { 0x11, 0x11 })]
        [TestCase(new object[] { 0x88, 0x88 })]
        [TestCase(new object[] { 0x33, 0x33 })]
        [TestCase(new object[] { 0xcc, 0xcc })]
        [TestCase(new object[] { 0x00, 0x00 })]
        [TestCase(new object[] { 0xff, 0xff })]
        [TestCase(new object[] { 0x11, 0x01 })]
        [TestCase(new object[] { 0x88, 0xab })]
        [TestCase(new object[] { 0x33, 0xcd })]
        [TestCase(new object[] { 0xcc, 0xef })]
        [TestCase(new object[] { 0x00, 0x38 })]
        [TestCase(new object[] { 0xff, 0x12 })]
        public void GMul_IsCommutative(byte left, byte right)
        {
            // Act
            byte r1 = GaloisMultiplication.GMul(left, right);
            byte r2 = GaloisMultiplication.GMul(right, left);


            // Assert
            Assert.AreEqual(r1, r2);
        }

        [TestCase(new object[] { new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 } })]
        [TestCase(new object[] { new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff } })]
        [TestCase(new object[] { new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, new byte[] { 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 } })]
        [TestCase(new object[] { new byte[] { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 }, new byte[] { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 } })]
        [TestCase(new object[] { new byte[] { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 }, new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 } })]
        [TestCase(new object[] { new byte[] { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 }, new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f } })]
        [TestCase(new object[] { new byte[] { 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03 }, new byte[] { 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc } })]
        [TestCase(new object[] { new byte[] { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 }, new byte[] { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 } })]
        [TestCase(new object[] { new byte[] { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c }, new byte[] { 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 } })]
        [TestCase(new object[] { new byte[] { 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0 }, new byte[] { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } })]
        public void GMul128_IsCommutative(byte[] left, byte[] right)
        {
            // Act
            byte[] r1 = GaloisMultiplication.GMul128(left, right);
            byte[] r2 = GaloisMultiplication.GMul128(right, left);


            // Assert
            Assert.IsTrue(r1.Select((s, i) => new { value = s, index = i }).All(a => a.value == r2[a.index]));
        }

        #endregion

        #region Distributive

        /// <summary>
        /// Distributive: (x+y)*z = (x*z) + (y*z) Addition is XOR
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        [TestCase(new object[] { 0x01, 0x10, 0x11 })]
        [TestCase(new object[] { 0x10, 0x01, 0xff })]
        [TestCase(new object[] { 0x08, 0x80, 0x88 })]
        [TestCase(new object[] { 0x80, 0x08, 0x00 })]
        [TestCase(new object[] { 0x03, 0x30, 0x33 })]
        [TestCase(new object[] { 0x30, 0x03, 0x88 })]
        [TestCase(new object[] { 0x0c, 0xc0, 0xcc })]
        [TestCase(new object[] { 0xc0, 0x0c, 0x44 })]
        [TestCase(new object[] { 0x11, 0x11, 0x80 })]
        [TestCase(new object[] { 0x88, 0x88, 0x01 })]
        [TestCase(new object[] { 0x33, 0x33, 0x50 })]
        [TestCase(new object[] { 0xcc, 0xcc, 0x05 })]
        [TestCase(new object[] { 0x00, 0x00, 0x00 })]
        [TestCase(new object[] { 0xff, 0xff, 0xff })]
        [TestCase(new object[] { 0x11, 0x01, 0x66 })]
        [TestCase(new object[] { 0x88, 0xab, 0x77 })]
        [TestCase(new object[] { 0x33, 0xcd, 0x22 })]
        [TestCase(new object[] { 0xcc, 0xef, 0xbb })]
        [TestCase(new object[] { 0x00, 0x38, 0xdd })]
        [TestCase(new object[] { 0xff, 0x12, 0xee })]
        public void GMul_IsDistributive(byte x, byte y, byte z)
        {
            // Act
            byte a1 = (byte)(x ^ y);
            byte r1 = GaloisMultiplication.GMul(a1, z);

            byte m1 = GaloisMultiplication.GMul(x, z);
            byte m2 = GaloisMultiplication.GMul(y, z);
            byte r2 = (byte)(m1 ^ m2);

            // Assert
            Assert.AreEqual(r1, r2);
        }

        /// <summary>
        /// Distributive: (x+y)*z = (x*z) + (y*z) Addition is XOR
        /// </summary>
        /// <param name="x"></param>
        /// <param name="y"></param>
        [TestCase(new object[] { new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, new byte[] { 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x99, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11, 0x00 }, new byte[] { 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0, 0xc0 } })]
        [TestCase(new object[] { new byte[] { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, new byte[] { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff }, new byte[] { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } })]
        [TestCase(new object[] { new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 }, new byte[] { 0xf0, 0xe0, 0xd0, 0xc0, 0xb0, 0xa0, 0x90, 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10, 0x00 }, new byte[] { 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c, 0x0c } })]
        [TestCase(new object[] { new byte[] { 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10, 0x10 }, new byte[] { 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0 }, new byte[] { 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88 } })]
        [TestCase(new object[] { new byte[] { 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08, 0x08 }, new byte[] { 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 }, new byte[] { 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30 } })]
        [TestCase(new object[] { new byte[] { 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80 }, new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f }, new byte[] { 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33 } })]
        public void GMul128_IsDistributive(byte[] x, byte[] y, byte[] z)
        {
            // Act
            byte[] a1 = Add(x, y);
            byte[] r1 = GaloisMultiplication.GMul128(a1, z);

            byte[] m1 = GaloisMultiplication.GMul128(x, z);
            byte[] m2 = GaloisMultiplication.GMul128(y, z);
            byte[] r2 = Add(m1, m2);

            // Assert
            Assert.IsTrue(r1.Select((s, i) => new { value = s, index = i }).All(a => a.value == r2[a.index]));
        }

        private byte[] Add(byte[] left, byte[] right)
        {
            byte[] z = new byte[left.Length];
            for (int i = 0; i < left.Length; i++)
                z[i] = (byte)(left[i] ^ right[i]);
            return z;
        }

        #endregion
    }
}
