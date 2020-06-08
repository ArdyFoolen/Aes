using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Aes.AF
{
    public static class RoundConstants
    {
        /// <summary>
        /// Start with 1
        /// Multiply previous constant by 2
        /// if result of previous calculation > 0x80
        ///     Xor with 0x11b. First 1 in the hex makes sure that that 8 bits does not get exceeded
        /// </summary>
        public static readonly byte[] Get = new byte[]
        {
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d 
        };
    }
}
