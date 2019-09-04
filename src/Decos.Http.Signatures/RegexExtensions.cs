using System;
using System.Collections.Generic;
using System.Text;
using System.Text.RegularExpressions;

namespace Decos.Http.Signatures
{
    internal static class RegexExtensions
    {
        public static string GetValueOrDefault(this Group group)
            => group.Success ? group.Value : null;
    }
}
