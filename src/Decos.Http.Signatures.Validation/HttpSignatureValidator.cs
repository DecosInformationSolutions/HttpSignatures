using System;
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
        /// Creates a new <see cref="HttpSignatureAlgorithm"/> object for validating a signature
        /// using the specified key identifier.
        /// </summary>
        /// <param name="keyId">
        /// An identifier for the key used to calculate or validate the signature.
        /// </param>
        /// <returns>A task that returns a new <see cref="HttpSignatureAlgorithm"/>.</returns>
        public virtual async Task<HttpSignatureAlgorithm> CreateAsync(string keyId)
        {
            var hasKey = await KeyLookup.TryGetKeyAsync(keyId, out var key);
            if (!hasKey)
                throw KeyNotFoundException.WithId(keyId);

            return new HttpSignatureAlgorithm(key, Clock);
        }

        ///// <summary>
        ///// Determines whether the signature is valid for the specified message.
        ///// </summary>
        ///// <param name="signature">The signature to validate.</param>
        ///// <returns>A value indicating the result of the validation.</returns>
        //public virtual SignatureValidationResult Validate(HttpSignatureAlgorithm signature,
        //    SignatureParams signatureParams)
        //{
        //    var timeDiff = Clock.UtcNow - timestamp;
        //    if (timeDiff.Duration() > Options.ClockSkewMargin)
        //        return SignatureValidationResult.Expired;

        // var entry = new NonceCacheEntry(nonce); if (Cache.TryGetValue(entry, out _)) return
        // SignatureValidationResult.Duplicate;

        // var newHash = signature.Calculate(message, nonce, timestamp); if
        // (!newHash.HashEquals(signature.Hash)) return SignatureValidationResult.Invalid;

        //    Cache.Set(entry, true, Options.NonceExpiration);
        //    return SignatureValidationResult.OK;
        //}
    }
}