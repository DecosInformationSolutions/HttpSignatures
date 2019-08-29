using System;
using System.IO;

namespace Decos.Http.Signatures
{
    public class HttpMessage
    {
        public string Method { get; set; }

        public string Uri { get; set; }

        public Stream Body { get; set; }
    }
}