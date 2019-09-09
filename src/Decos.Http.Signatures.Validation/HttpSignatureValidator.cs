using System;
using System.IO;
using System.Threading.Tasks;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Decos.Http.Signatures.Validation
{
    /// <summary>
    /// Validates signed HTTP messages.
    /// </summary>
    public class HttpSignatureValidator
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HttpSignatureValidator"/> class with the
        /// specified dependencies.
        /// </summary>
        /// <param name="keyLookup">A mechanism for looking up signing keys.</param>
        /// <param name="cache">A cache used to store used nonces.</param>
        /// <param name="clock">A mechanism for retrieving the current system time.</param>
        /// <param name="options">
        /// Options used to control signature calculation and validation.
        /// </param>
        public HttpSignatureValidator(IKeyLookup keyLookup,
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
        /// Determines whether the signature is valid for the specified message.
        /// </summary>
        /// <param name="signature">The signature to validate.</param>
        /// <param name="method">The HTTP method of the message.</param>
        /// <param name="uri">The requested URI of the message.</param>
        /// <param name="body">The message body.</param>
        /// <returns>A value indicating the result of the validation.</returns>
        public virtual async Task<SignatureValidationResult> ValidateAsync(
            HttpSignature signature, string method, string uri, Stream body)
        {
            var timeDiff = Clock.UtcNow - signature.Timestamp;
            if (timeDiff.Duration() > Options.ClockSkewMargin)
                return SignatureValidationResult.Expired;

            var entry = new NonceCacheEntry(signature.Nonce);
            if (Cache.TryGetValue(entry, out _))
                return SignatureValidationResult.Duplicate;

            var hasKey = await KeyLookup.TryGetKeyAsync(signature.KeyId, out var key).ConfigureAwait(false);
            if (!hasKey)
                throw KeyNotFoundException.WithId(signature.KeyId);

            var algorithm = new HttpSignatureAlgorithm(key, Clock);
            var newHash = algorithm.CalculateHash(method, uri, body, signature.Nonce,
                signature.Timestamp);
            if (!newHash.HashEquals(signature.Hash))
                return SignatureValidationResult.Invalid;

            Cache.Set(entry, true, Options.NonceExpiration);
            return SignatureValidationResult.OK;
        }
    }
}