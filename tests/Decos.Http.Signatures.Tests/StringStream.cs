using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Decos.Http.Signatures.Tests
{
    public class StringStream : MemoryStream
    {
        public StringStream(string value)
            : this(value, Encoding.UTF8)
        {
        }

        public StringStream(string value, Encoding encoding)
            : base(encoding.GetBytes(value))
        {
            Encoding = encoding;
        }

        public Encoding Encoding { get; }

        public override string ToString() => Encoding.GetString(ToArray());
    }
}
