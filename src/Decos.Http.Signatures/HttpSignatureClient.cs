using System;
using System.Threading.Tasks;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Decos.Http.Signatures
{
    public class HttpSignatureClient
    {
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

        protected IMemoryCache Cache { get; }

        protected ISystemClock Clock { get; }

        protected IKeyLookup KeyLookup { get; }

        protected SignatureOptions Options { get; }

        public async Task<HttpSignature> CreateAsync(string keyId,
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
        /// Determines whether the signature is valid for the specified message.
        /// </summary>
        /// <param name="signature">The signature to validate.</param>
        /// <param name="message">The signed HTTP message.</param>
        /// <param name="nonce">The signature nonce.</param>
        /// <param name="timestamp">The signature timestamp.</param>
        /// <returns>A value indicating the result of the validation.</returns>
        public SignatureValidationResult Validate(HttpSignature signature,
            HttpMessage message, string nonce, DateTimeOffset timestamp)
        {
            var timeDiff = Clock.UtcNow - timestamp;
            if (timeDiff.Duration() > Options.ClockSkewMargin)
                return SignatureValidationResult.Expired;

            var entry = new NonceCacheEntry(nonce);
            if (Cache.TryGetValue(entry, out _))
                return SignatureValidationResult.Duplicate;

            if (!signature.Validate(message, nonce, timestamp))
                return SignatureValidationResult.Invalid;

            Cache.Set(entry, true, Options.NonceExpiration);
            return SignatureValidationResult.OK;
        }
    }
}