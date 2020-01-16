using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
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
        /// Initializes a new instance of the <see cref="HttpSignatureValidator"/> class with the
        /// specified dependencies.
        /// </summary>
        /// <param name="keyLookup">A mechanism for looking up signing keys.</param>
        /// <param name="cache">A cache used to store used nonces.</param>
        /// <param name="clock">A mechanism for retrieving the current system time.</param>
        /// <param name="options">
        /// Options used to control signature calculation and validation.
        /// </param>
        /// <param name="logger"></param>
        public HttpSignatureValidator(IKeyLookup keyLookup,
            IMemoryCache cache,
            ISystemClock clock,
            IOptions<SignatureOptions> options,
            ILogger<HttpSignatureValidator> logger)
            : this(keyLookup, cache, clock, options)
        {
            Logger = logger;
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
        /// Gets a logger for writing log events, or <c>null</c>.
        /// </summary>
        protected ILogger<HttpSignatureValidator> Logger { get; }

        /// <summary>
        /// Determines whether the signature is valid for the specified message.
        /// </summary>
        /// <param name="signature">The signature to validate.</param>
        /// <param name="method">The HTTP method of the message.</param>
        /// <param name="uri">The requested URI of the message.</param>
        /// <param name="body">The message body.</param>
        /// <returns>A value indicating the result of the validation.</returns>
        public Task<SignatureValidationResult> ValidateAsync(
            HttpSignature signature, string method, string uri, Stream body)
            => ValidateAsync(signature, method, uri, body, default);

        /// <summary>
        /// Determines whether the signature is valid for the specified message.
        /// </summary>
        /// <param name="signature">The signature to validate.</param>
        /// <param name="method">The HTTP method of the message.</param>
        /// <param name="uri">The requested URI of the message.</param>
        /// <param name="body">The message body.</param>
        /// <param name="cancellationToken">A token to monitor for cancellation requests.</param>
        /// <returns>A value indicating the result of the validation.</returns>
        public virtual async Task<SignatureValidationResult> ValidateAsync(
            HttpSignature signature, string method, string uri, Stream body,
            CancellationToken cancellationToken)
        {
            var timeDiff = Clock.UtcNow - signature.Timestamp;
            if (timeDiff.Duration() > Options.ClockSkewMargin)
            {
                Logger?.LogInformation("The time difference {TimeDiff} between the signature timestamp {Timestamp} and the current time exceeds {Margin}.",
                    timeDiff, signature.Timestamp, Options.ClockSkewMargin);
                return SignatureValidationResult.Expired;
            }

            var entry = new NonceCacheEntry(signature.Nonce);
            if (Cache.TryGetValue(entry, out _))
            {
                Logger?.LogInformation("The nonce '{Nonce}' is not unique and has been used before in the past {Expiration}.",
                    signature.Nonce, Options.NonceExpiration);
                return SignatureValidationResult.Duplicate;
            }

            var key = await KeyLookup.GetKeyOrDefaultAsync(signature.KeyId).ConfigureAwait(false);
            if (key == null)
                throw KeyNotFoundException.WithId(signature.KeyId);

            var algorithm = new HttpSignatureAlgorithm(key, Clock, Logger);
            var newHash = await algorithm.CalculateHashAsync(method, uri, body, signature.Nonce,
                signature.Timestamp, cancellationToken).ConfigureAwait(false);
            if (!newHash.HashEquals(signature.Hash))
            {
                Logger?.LogInformation("The signature for {Method} {Uri} with nonce '{Nonce}' and timestamp {Timestamp} does not match.",
                    method, uri, signature.Nonce, signature.Timestamp);
                return SignatureValidationResult.Invalid;
            }

            Cache.Set(entry, true, Options.NonceExpiration);
            return SignatureValidationResult.OK;
        }
    }
}