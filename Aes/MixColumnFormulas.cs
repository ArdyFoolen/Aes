using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Aes.AF.GaloisMultiplication;

namespace Aes.AF
{
    public static class MixColumnFormulas
    {
        /// <summary>
        /// | 0x02 0x03 0x01 0x01 |
        /// | 0x01 0x02 0x03 0x01 |
        /// | 0x01 0x01 0x02 0x03 |
        /// | 0x03 0x01 0x01 0x02 |
        /// </summary>
        public static readonly Func<int, byte[], byte>[] Get = new Func<int, byte[], byte>[]
        {
            (column, input) => (byte)(GMul((byte)2, input[0 + 4 * column]) ^ GMul((byte)3, input[1 + 4 * column]) ^               input[2 + 4 * column]  ^               input[3 + 4 * column]),
            (column, input) => (byte)(              input[0 + 4 * column]  ^ GMul((byte)2, input[1 + 4 * column]) ^ GMul((byte)3, input[2 + 4 * column]) ^               input[3 + 4 * column]),
            (column, input) => (byte)(              input[0 + 4 * column]  ^               input[1 + 4 * column]  ^ GMul((byte)2, input[2 + 4 * column]) ^ GMul((byte)3, input[3 + 4 * column])),
            (column, input) => (byte)(GMul((byte)3, input[0 + 4 * column]) ^               input[1 + 4 * column]  ^               input[2 + 4 * column]  ^ GMul((byte)2, input[3 + 4 * column]))
        };

        /// <summary>
        /// | 0x0E 0x0B 0x0D 0x09 |
        /// | 0x09 0x0E 0x0B 0x0D |
        /// | 0x0D 0x09 0x0E 0x0B |
        /// | 0x0B 0x0D 0x09 0x0E |
        /// </summary>
        public static readonly Func<int, byte[], byte>[] Inverse = new Func<int, byte[], byte>[]
        {
            (column, input) => (byte)(GMul((byte)0xE, input[0 + 4 * column]) ^ GMul((byte)0xB, input[1 + 4 * column]) ^ GMul((byte)0xD, input[2 + 4 * column]) ^ GMul((byte)0x9, input[3 + 4 * column])),
            (column, input) => (byte)(GMul((byte)0x9, input[0 + 4 * column]) ^ GMul((byte)0xE, input[1 + 4 * column]) ^ GMul((byte)0xB, input[2 + 4 * column]) ^ GMul((byte)0xD, input[3 + 4 * column])),
            (column, input) => (byte)(GMul((byte)0xD, input[0 + 4 * column]) ^ GMul((byte)0x9, input[1 + 4 * column]) ^ GMul((byte)0xE, input[2 + 4 * column]) ^ GMul((byte)0xB, input[3 + 4 * column])),
            (column, input) => (byte)(GMul((byte)0xB, input[0 + 4 * column]) ^ GMul((byte)0xD, input[1 + 4 * column]) ^ GMul((byte)0x9, input[2 + 4 * column]) ^ GMul((byte)0xE, input[3 + 4 * column])),
        };
    }
}
