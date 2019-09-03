using System;
using System.Collections.Generic;
using System.Diagnostics.Tracing;
using System.Text;

namespace Decos.Http.Signatures
{
    internal readonly struct NonceCacheEntry
    {
        public static readonly NonceCacheEntry None = new NonceCacheEntry();

        public NonceCacheEntry(string nonce)
        {
            Value = nonce;
        }

        public string Value { get; }
    }
}
