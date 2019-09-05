using System;
using System.Text;

namespace Decos.Http.Signatures
{
    public class SignatureData
    {
        public SignatureData(string method,
            string uri,
            string nonce,
            DateTimeOffset timestamp,
            byte[] contentHash)
        {
            if (method is null)
                throw new ArgumentNullException(nameof(method));

            if (uri is null)
                throw new ArgumentNullException(nameof(uri));

            if (nonce is null)
                throw new ArgumentNullException(nameof(nonce));

            if (contentHash is null)
                throw new ArgumentNullException(nameof(contentHash));

            Method = method;
            Uri = uri;
            Nonce = nonce;
            Timestamp = timestamp;
            ContentHash = contentHash;
        }

        public string Method { get; }

        public string Uri { get; }

        public string Nonce { get; }

        public DateTimeOffset Timestamp { get; }

        public byte[] ContentHash { get; }

        public byte[] GetRawData()
        {
            var builder = new StringBuilder();
            builder.Append(Method.ToUpperInvariant());
            builder.Append(" ");
            builder.AppendLine(Uri);
            builder.AppendLine(Nonce);
            builder.AppendLine(Timestamp.ToUnixTimeSeconds().ToString());
            builder.AppendLine(Convert.ToBase64String(ContentHash));
            return Encoding.UTF8.GetBytes(builder.ToString());
        }
    }
}