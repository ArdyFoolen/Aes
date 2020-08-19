using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF
{
    public class AuthenticatedException : Exception
    {
        public AuthenticatedException(string message) : base(message) { }
    }
}
