using System;
using System.Collections.Generic;
using System.Text;

namespace Aes.AF.Extensions
{
    public static class UsingExtensions
    {
        public static TResult Using<TDisp, TResult>(this TDisp disposable, Func<TDisp, TResult> func)
            where TDisp : IDisposable
        {
            using (disposable) { return func(disposable); }
        }
        public static void Using<TDisp>(this TDisp disposable, Action<TDisp> action)
            where TDisp : IDisposable
        {
            using (disposable) { action(disposable); }
        }
    }
}
