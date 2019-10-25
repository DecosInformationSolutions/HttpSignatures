using System;
using System.IO;
using System.Security.Cryptography;
using Microsoft.Extensions.Logging;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Generates signatures for HTTP messages.
    /// </summary>
    public class HttpSignatureAlgorithm
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSignatureAlgorithm"/> class with the
        /// specified key.
        /// </summary>
        /// <param name="key">The key used to generate signatures.</param>
        public HttpSignatureAlgorithm(byte[] key)
            : this(key, new SystemClock())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSignatureAlgorithm"/> class with the
        /// specified key and system clock mechanism.
        /// </summary>
        /// <param name="key">The key used to generate signatures.</param>
        /// <param name="clock">A mechanism used to retrieve the current time.</param>
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
        /// Initializes a new instance of the <see cref="HttpSignatureAlgorithm"/> class with the
        /// specified key and system clock mechanism. This instance will have logging enabled.
        /// </summary>
        /// <param name="key">The key used to generate signatures.</param>
        /// <param name="clock">A mechanism used to retrieve the current time.</param>
        /// <param name="logger">A logger used to write debugging output.</param>
        public HttpSignatureAlgorithm(byte[] key, ISystemClock clock, ILogger logger)
            : this(key, clock)
        {
            Logger = logger;
        }

        /// <summary>
        /// Gets the key used in the signature calculation.
        /// </summary>
        public byte[] Key { get; }

        /// <summary>
        /// Gets a mechanism for retrieving the current time.
        /// </summary>
        protected ISystemClock Clock { get; }

        /// <summary>
        /// Gets a logger for writing debugging output, or <c>null</c>.
        /// </summary>
        protected ILogger Logger { get; }

        /// <summary>
        /// Calculates a new signature for the specified parameters, using a new nonce and timestamp.
        /// </summary>
        /// <param name="method">The HTTP method of the message.</param>
        /// <param name="uri">The request URI of the message.</param>
        /// <param name="stream">A stream that contains the message body.</param>
        /// <param name="nonce">
        /// When this method returns, contains the nonce used to calculate the signature.
        /// </param>
        /// <param name="timestamp">
        /// When this method returns, contains the point in time the signature was created.
        /// </param>
        /// <returns>A byte array that contains the calculated signature hash.</returns>
        public byte[] CalculateHash(string method, string uri, Stream stream,
            out string nonce, out DateTimeOffset timestamp)
        {
            nonce = Guid.NewGuid().ToString();
            timestamp = Clock.UtcNow;
            return CalculateHash(method, uri, stream, nonce, timestamp);
        }

        /// <summary>
        /// Calculates a new signature for the specified parameters using the specified nonce and
        /// timestamp.
        /// </summary>
        /// <param name="method">The HTTP method of the message.</param>
        /// <param name="uri">The request URI of the message.</param>
        /// <param name="stream">A stream that contains the message body.</param>
        /// <param name="nonce">The nonce used to calculate the signature.</param>
        /// <param name="timestamp">The point in time the signature was created.</param>
        /// <returns>A byte array that contains the calculated signature hash.</returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="method"/> or <paramref name="uri"/> is <c>null</c>.
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
            Logger?.LogDebug("Calculating a signature with the following data: {Data}", signatureData);
            return CalculateHash(signatureData);
        }

        /// <summary>
        /// Calculates a new signature for the specified parameters.
        /// </summary>
        /// <param name="signatureData">The data used in the signature.</param>
        /// <returns>A byte array that contains the calculated signature hash.</returns>
        public virtual byte[] CalculateHash(SignatureData signatureData)
        {
            using (var hmac = new HMACSHA256(Key))
            {
                var hashData = signatureData.ToByteArray();
                return hmac.ComputeHash(hashData);
            }
        }

        /// <summary>
        /// Calculates a general purpose hash of the stream's content.
        /// </summary>
        /// <param name="stream">
        /// The stream whose content is used to calculate a hash. If seeking is supported, the stream
        /// is reset to its original position when this method returns.
        /// </param>
        /// <returns>A byte array that contains the calculated hash.</returns>
        protected byte[] CalculateContentHash(Stream stream)
        {
            byte[] contentHash;
            using (var sha256 = SHA256.Create())
            {
                if (stream == null)
                    return sha256.ComputeHash(new byte[0]);

                long? offset = null;
                if (stream.CanSeek)
                {
                    offset = stream.Position;
                    stream.Seek(0, SeekOrigin.Begin);
                }

                contentHash = sha256.ComputeHash(stream);

                if (stream.CanSeek && offset != null)
                    stream.Seek(offset.Value, SeekOrigin.Begin);
            }
            return contentHash;
        }
    }
}