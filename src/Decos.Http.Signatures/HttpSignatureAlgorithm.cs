using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Logging;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Generates signatures for HTTP messages.
    /// </summary>
    public class HttpSignatureAlgorithm
    {
        private const int ContentBufferSize = 8192;

        private static readonly byte[] s_emptyHash = new byte[]
        {
            0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
            0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
            0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
            0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55
        };

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
        /// Calculates a new signature for the specified parameters, using a new nonce and
        /// timestamp.
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
        [Obsolete("Use " + nameof(CalculateHashAsync) + " instead.")]
        public byte[] CalculateHash(string method, string uri, Stream stream,
            out string nonce, out DateTimeOffset timestamp)
        {
            nonce = Guid.NewGuid().ToString();
            timestamp = Clock.UtcNow;
            return CalculateHash(method, uri, stream, nonce, timestamp);
        }

        /// <summary>
        /// Calculates a new signature for the specified parameters, generating a new nonce and
        /// timestamp.
        /// </summary>
        /// <param name="method">The HTTP method of the message.</param>
        /// <param name="uri">The request URI of the message.</param>
        /// <param name="stream">A stream that contains the message body.</param>
        /// <param name="cancellationToken">
        /// A token used to monitor for cancellation requests.
        /// </param>
        /// <returns>
        /// A task that returns a tuple containing the following items:
        /// <list type="number">
        /// <item>a byte array that contains the calculated signature hash;</item>
        /// <item>a string that contains the nonce used;</item>
        /// <item>
        /// a DateTimeOffset that represents the point in time the signature was created.
        /// </item>
        /// </list>
        /// </returns>
        public async Task<(byte[] hash, string nonce, DateTimeOffset timestamp)> CalculateHashAsync(
            string method, string uri, Stream stream, CancellationToken cancellationToken = default)
        {
            var nonce = Guid.NewGuid().ToString();
            var timestamp = Clock.UtcNow;
            var hash = await CalculateHashAsync(method, uri, stream, nonce, timestamp, cancellationToken).ConfigureAwait(false);
            return (hash, nonce, timestamp);
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
        [Obsolete("Use " + nameof(CalculateHashAsync) + " instead.")]
        public byte[] CalculateHash(string method, string uri, Stream stream,
            string nonce, DateTimeOffset timestamp)
        {
            return CalculateHashAsync(method, uri, stream, nonce, timestamp, default)
                .ConfigureAwait(false).GetAwaiter().GetResult();
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
        /// <param name="cancellationToken">
        /// A token used to monitor for cancellation requests.
        /// </param>
        /// <returns>
        /// A task that returns a byte array that contains the calculated signature hash.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// <paramref name="method"/> or <paramref name="uri"/> is <c>null</c>.
        /// </exception>
        /// <exception cref="ArgumentException">
        /// <paramref name="nonce"/> or <paramref name="timestamp"/> are not specified.
        /// </exception>
        public async Task<byte[]> CalculateHashAsync(string method, string uri, Stream stream,
            string nonce, DateTimeOffset timestamp, CancellationToken cancellationToken = default)
        {
            if (method == null)
                throw new ArgumentNullException(nameof(method));

            if (uri == null)
                throw new ArgumentNullException(nameof(uri));

            if (string.IsNullOrEmpty(nonce))
                throw new ArgumentException("A nonce must be specified.", nameof(nonce));

            if (timestamp == default)
                throw new ArgumentException("A timestamp must be specified.", nameof(timestamp));

            var contentHash = await CalculateContentHashAsync(stream, cancellationToken).ConfigureAwait(false);
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
        /// The stream whose content is used to calculate a hash. If seeking is supported, the
        /// stream is reset to its original position when this method returns.
        /// </param>
        /// <returns>A byte array that contains the calculated hash.</returns>
        [Obsolete("Use " + nameof(CalculateContentHashAsync) + " instead.")]
        protected byte[] CalculateContentHash(Stream stream)
        {
            return CalculateContentHashAsync(stream, default)
                .ConfigureAwait(false).GetAwaiter().GetResult();
        }

        /// <summary>
        /// Calculates a general purpose hash of the stream's content.
        /// </summary>
        /// <param name="stream">
        /// The stream whose content is used to calculate a hash. If seeking is supported, the
        /// stream is reset to its original position when this method returns.
        /// </param>
        /// <param name="cancellationToken">
        /// A token used to monitor for cancellation requests.
        /// </param>
        /// <returns>A task that returns a byte array that contains the calculated hash.</returns>
        protected async Task<byte[]> CalculateContentHashAsync(Stream stream, CancellationToken cancellationToken)
        {
            byte[] contentHash;
            using (var sha256 = SHA256.Create())
            {
                if (stream == null)
                    return s_emptyHash;

                long? offset = null;
                if (stream.CanSeek)
                {
                    offset = stream.Position;
                    stream.Seek(0, SeekOrigin.Begin);
                }

                var buffer = new byte[ContentBufferSize];
                var bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length, cancellationToken)
                    .ConfigureAwait(false);
                contentHash = sha256.ComputeHash(buffer, 0, bytesRead);

                if (stream.CanSeek && offset != null)
                    stream.Seek(offset.Value, SeekOrigin.Begin);
            }
            return contentHash;
        }
    }
}