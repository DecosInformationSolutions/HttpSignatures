using System;
using System.IO;
using System.Security.Cryptography;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Generates signatures for HTTP messages.
    /// </summary>
    public class HttpSignatureAlgorithm
    {
        public HttpSignatureAlgorithm(byte[] key)
            : this(key, new SystemClock())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSignatureAlgorithm"/> class with the
        /// specified key.
        /// </summary>
        /// <param name="key">The key used to generate signatures.</param>
        public HttpSignatureAlgorithm(byte[] key, ISystemClock clock)
        {
            if (key is null)
                throw new ArgumentNullException(nameof(key));

            if (key.Length == 0)
                throw new ArgumentException("The key must not be empty.", nameof(key));

            if (clock == null)
                throw new ArgumentNullException(nameof(clock));

            Key = key;
            Clock = clock;
        }

        /// <summary>
        /// Gets or sets the key used in the signature calculation.
        /// </summary>
        public byte[] Key { get; }

        protected ISystemClock Clock { get; }

        public byte[] CalculateHash(string method, string uri, Stream stream,
            out string nonce, out DateTimeOffset timestamp)
        {
            nonce = Guid.NewGuid().ToString();
            timestamp = Clock.UtcNow;
            return CalculateHash(method, uri, stream, nonce, timestamp);
        }

        /// <summary>
        /// Calculates a new signature for the specified parameters.
        /// </summary>
        /// <param name="message">The HTTP message to calculate a signature for.</param>
        /// <param name="nonce">A unique value for the signature.</param>
        /// <param name="timestamp">A timestamp for the signature.</param>
        /// <returns>The new signature.</returns>
        /// <exception cref="InvalidOperationException">
        /// <see cref="Key"/>, <see cref="Algorithm"/> or <see cref="ContentAlgorithm"/> are not
        /// specified.
        /// </exception>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="message"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="nonce"/> or <paramref name="timestamp"/> are not specified.
        /// </exception>
        public byte[] CalculateHash(string method, string uri, Stream stream,
            string nonce, DateTimeOffset timestamp)
        {
            if (method == null)
                throw new ArgumentNullException(nameof(method));

            if (uri == null)
                throw new ArgumentNullException(nameof(uri));

            if (string.IsNullOrEmpty(nonce))
                throw new ArgumentException("A nonce must be specified.", nameof(nonce));

            if (timestamp == default)
                throw new ArgumentException("A timestamp must be specified.", nameof(timestamp));

            var contentHash = CalculateContentHash(stream);
            var signatureData = new SignatureData(method, uri, nonce, timestamp, contentHash);
            return CalculateHash(signatureData);
        }

        /// <summary>
        /// Calculates a new signature for the specified parameters.
        /// </summary>
        /// <returns>A byte array that contains the hash.</returns>
        public virtual byte[] CalculateHash(SignatureData signatureData)
        {
            using (var hmac = new HMACSHA256(Key))
            {
                var hashData = signatureData.GetRawData();
                return hmac.ComputeHash(hashData);
            }
        }

        protected byte[] CalculateContentHash(Stream stream)
        {
            byte[] contentHash;
            using (var sha256 = SHA256.Create())
            {
                if (stream == null)
                    return sha256.ComputeHash(new byte[0]);

                var offset = stream.Position;
                if (stream.CanSeek)
                    stream.Seek(0, SeekOrigin.Begin);

                contentHash = sha256.ComputeHash(stream);

                if (stream.CanSeek)
                    stream.Seek(offset, SeekOrigin.Begin);
            }
            return contentHash;
        }
    }
}