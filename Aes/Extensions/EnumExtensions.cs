using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF.Extensions
{
    public static class EnumExtensions
    {
        public static T ToEnum<T>(this string s)
            where T : Enum
            => (T)Enum.Parse(typeof(T), s);
    }
}
