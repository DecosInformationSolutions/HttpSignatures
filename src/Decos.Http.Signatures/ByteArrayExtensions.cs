using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace Decos.Http.Signatures
{
    public static class ByteArrayExtensions
    {
        public static bool HashEquals(this byte[] value, byte[] other)
        {
            var diff = (uint)value.Length ^ (uint)other.Length;
            for (int i = 0; i < value.Length && i < other.Length; i++)
                diff |= (uint)(value[i] ^ other[i]);
            return diff == 0;
        }
    }
}
