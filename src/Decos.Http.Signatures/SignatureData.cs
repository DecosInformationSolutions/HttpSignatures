using System;
using System.Text;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Represents the data used in a signature.
    /// </summary>
    public class SignatureData
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureData"/> class.
        /// </summary>
        /// <param name="method">The HTTP method.</param>
        /// <param name="uri">The requested URI.</param>
        /// <param name="nonce">The nonce.</param>
        /// <param name="timestamp">The signature timestamp.</param>
        /// <param name="contentHash">The content hash.</param>
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

        /// <summary>
        /// Gets the HTTP method.
        /// </summary>
        public string Method { get; }

        /// <summary>
        /// Gets the requested URI.
        /// </summary>
        public string Uri { get; }

        /// <summary>
        /// Gets the nonce.
        /// </summary>
        public string Nonce { get; }

        /// <summary>
        /// Gets the signature timestamp.
        /// </summary>
        public DateTimeOffset Timestamp { get; }

        /// <summary>
        /// Gets a hash of the message body.
        /// </summary>
        public byte[] ContentHash { get; }

        /// <summary>
        /// Returns a byte array unique to the message which can be used to calculate a hash.
        /// </summary>
        /// <returns>A new byte array that represents the signature data.</returns>
        public byte[] ToByteArray()
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