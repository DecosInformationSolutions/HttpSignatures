using System;
using System.Threading.Tasks;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Provides signature calculation and validation.
    /// </summary>
    public class HttpSignatureClient
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSignatureClient"/> class with the
        /// specified dependencies.
        /// </summary>
        /// <param name="keyLookup">A mechanism for looking up signing keys.</param>
        /// <param name="cache">A cache used to store used nonces.</param>
        /// <param name="clock">A mechanism for retrieving the current system time.</param>
        /// <param name="options">
        /// Options used to control signature calculation and validation.
        /// </param>
        public HttpSignatureClient(IKeyLookup keyLookup,
            IMemoryCache cache,
            ISystemClock clock,
            IOptions<SignatureOptions> options)
        {
            KeyLookup = keyLookup;
            Cache = cache;
            Clock = clock;
            Options = options.Value;
        }

        /// <summary>
        /// Gets a cache used to store used nonces.
        /// </summary>
        protected IMemoryCache Cache { get; }

        /// <summary>
        /// Gets a mechanism for retrieving the current system time.
        /// </summary>
        protected ISystemClock Clock { get; }

        /// <summary>
        /// Gets a mechanism for looking up signing keys.
        /// </summary>
        protected IKeyLookup KeyLookup { get; }

        /// <summary>
        /// Gets the options used to control signature calculation and validation.
        /// </summary>
        protected SignatureOptions Options { get; }

        /// <summary>
        /// Creates a new <see cref="HttpSignature"/> object for calculating or validating a
        /// signature with the specified parameters.
        /// </summary>
        /// <param name="keyId">
        /// An identifier for the key used to calculate or validate the signature.
        /// </param>
        /// <param name="algorithm">
        /// The name of a keyed hash algorithm used to calculate the signature. This parameter is
        /// optional.
        /// </param>
        /// <param name="contentAlgorithm">
        /// The name of a hash algorithm used to calculate the content hash. This parameter is
        /// optional.
        /// </param>
        /// <param name="signature">
        /// If representing an existing signature, the hash of the signature. To generate new
        /// signatures, this can be left <c>null</c>.
        /// </param>
        /// <returns>A task that returns a new <see cref="HttpSignature"/>.</returns>
        public virtual async Task<HttpSignature> CreateAsync(string keyId,
            string algorithm = null,
            string contentAlgorithm = null,
            byte[] signature = null)
        {
            var hasKey = await KeyLookup.TryGetKeyAsync(keyId, out var key);
            if (!hasKey)
                throw KeyNotFoundException.WithId(keyId);

            return new HttpSignature
            {
                Key = key,
                Algorithm = algorithm ?? Options.DefaultAlgorithm,
                ContentAlgorithm = contentAlgorithm ?? Options.DefaultContentAlgorithm,
                Hash = signature
            };
        }

        /// <summary>
        /// Calculates a new signature for the specified message.
        /// </summary>
        /// <param name="signature">
        /// The <see cref="HttpSignature"/> used to calculate a signature.
        /// </param>
        /// <param name="message">The message to calculate a signature for.</param>
        /// <param name="nonce">When this method returns, contains the signature nonce.</param>
        /// <param name="timestamp">
        /// When this method returns, contains the signature timestamp.
        /// </param>
        /// <returns>A byte array that represents the signature hash.</returns>
        public virtual byte[] Calculate(HttpSignature signature,
            HttpMessage message, out string nonce, out DateTimeOffset timestamp)
        {
            nonce = Guid.NewGuid().ToString();
            timestamp = Clock.UtcNow;
            return signature.Calculate(message, nonce, timestamp);
        }

        /// <summary>
        /// Determines whether the signature is valid for the specified message.
        /// </summary>
        /// <param name="signature">The signature to validate.</param>
        /// <param name="message">The signed HTTP message.</param>
        /// <param name="nonce">The signature nonce.</param>
        /// <param name="timestamp">The signature timestamp.</param>
        /// <returns>A value indicating the result of the validation.</returns>
        public virtual SignatureValidationResult Validate(HttpSignature signature,
            HttpMessage message, string nonce, DateTimeOffset timestamp)
        {
            var timeDiff = Clock.UtcNow - timestamp;
            if (timeDiff.Duration() > Options.ClockSkewMargin)
                return SignatureValidationResult.Expired;

            var entry = new NonceCacheEntry(nonce);
            if (Cache.TryGetValue(entry, out _))
                return SignatureValidationResult.Duplicate;

            var newHash = signature.Calculate(message, nonce, timestamp);
            if (!newHash.HashEquals(signature.Hash))
                return SignatureValidationResult.Invalid;

            Cache.Set(entry, true, Options.NonceExpiration);
            return SignatureValidationResult.OK;
        }
    }
}