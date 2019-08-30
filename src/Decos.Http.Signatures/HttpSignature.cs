using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Represents a signature in an HTTP request or response message.
    /// </summary>
    public class HttpSignature
    {
        /// <summary>
        /// Gets or sets the key used in the signature calculation.
        /// </summary>
        public byte[] Key { get; set; }

        /// <summary>
        /// Gets or sets the name of the keyed hash algorithm to use for the signature.
        /// </summary>
        public string Algorithm { get; set; }

        /// <summary>
        /// Gets or sets the name of the hash algorithm to use for the content.
        /// </summary>
        public string ContentAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the calculated signature.
        /// </summary>
        public byte[] Signature { get; set; }

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
        public byte[] Calculate(HttpMessage message,
            string nonce, DateTimeOffset timestamp)
        {
            if (Key == null || Key.Length == 0)
                throw new InvalidOperationException("A key must be specified.");

            if (string.IsNullOrEmpty(Algorithm))
                throw new InvalidOperationException("An algorithm must be specified.");

            if (string.IsNullOrEmpty(ContentAlgorithm))
                throw new InvalidOperationException("A content hash algorithm must be specified.");

            if (message == null)
                throw new ArgumentNullException(nameof(message));

            if (string.IsNullOrEmpty(nonce))
                throw new ArgumentException("A nonce must be specified.", nameof(nonce));

            if (timestamp == default)
                throw new ArgumentException("A timestamp must be specified.", nameof(timestamp));

            return CalculateCore(message, nonce, timestamp);
        }

        /// <summary>
        /// Checks whether the calculated signature is correct for the specified parameters.
        /// </summary>
        /// <param name="message">The HTTP message that was used to calculate the signature.</param>
        /// <param name="nonce">A unique value for the signature.</param>
        /// <param name="timestamp">A timestamp for the signature.</param>
        /// <returns><c>true</c> if the signature is valid; otherwise, <c>false</c>.</returns>
        public bool Validate(HttpMessage message,
            string nonce, DateTimeOffset timestamp)
        {
            var newHash = Calculate(message, nonce, timestamp);
            return newHash.HashEquals(Signature);
        }

        /// <summary>
        /// Calculates a new signature for the specified parameters.
        /// </summary>
        /// <param name="message">The HTTP message to calculate a signature for.</param>
        /// <param name="nonce">A unique value for the signature.</param>
        /// <param name="timestamp">A timestamp for the signature.</param>
        /// <returns>A byte array that contains the hash.</returns>
        protected virtual byte[] CalculateCore(HttpMessage message,
            string nonce, DateTimeOffset timestamp)
        {
            var contentHash = CalculateContentHash(message);
            var signatureData = new SignatureData
            {
                Target = $"{message.Method.ToUpperInvariant()} {message.Uri}",
                Nonce = nonce,
                Timestamp = timestamp,
                ContentHash = contentHash
            };

            using (var keyedHash = KeyedHashAlgorithm.Create(Algorithm))
            {
                keyedHash.Key = Key;

                var hashData = signatureData.GetRawData();
                return keyedHash.ComputeHash(hashData);
            }
        }

        private byte[] CalculateContentHash(HttpMessage message)
        {
            byte[] contentHash;
            using (var hash = HashAlgorithm.Create(ContentAlgorithm))
            {
                var offset = message.Body.Position;
                if (message.Body.CanSeek)
                    message.Body.Seek(0, SeekOrigin.Begin);

                contentHash = hash.ComputeHash(message.Body);

                if (message.Body.CanSeek)
                    message.Body.Seek(offset, SeekOrigin.Begin);
            }

            return contentHash;
        }

        private class SignatureData
        {
            public string Target { get; set; }

            public string Nonce { get; set; }

            public DateTimeOffset Timestamp { get; set; }

            public byte[] ContentHash { get; set; }

            public byte[] GetRawData()
            {
                var builder = new StringBuilder();
                builder.AppendLine(Target);
                builder.AppendLine(Nonce);
                builder.AppendLine(Timestamp.ToUnixTimeSeconds().ToString());
                builder.AppendLine(Convert.ToBase64String(ContentHash));
                return Encoding.UTF8.GetBytes(builder.ToString());
            }
        }
    }
}