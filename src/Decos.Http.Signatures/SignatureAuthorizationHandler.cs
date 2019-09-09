using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Represents an HTTP handler that adds a signature to outgoing requests in the Authorization
    /// header.
    /// </summary>
    public class SignatureAuthorizationHandler : DelegatingHandler
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureAuthorizationHandler"/> class with
        /// the specified key ID and key, using the default HTTP client handler as inner handler.
        /// </summary>
        /// <param name="keyId">An identifier for <paramref name="key"/>.</param>
        /// <param name="key">The key used to calculate signatures.</param>
        public SignatureAuthorizationHandler(string keyId, byte[] key)
            : this(keyId, new HttpSignatureAlgorithm(key))
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureAuthorizationHandler"/> class with
        /// the specified key ID and algorithm, using the default HTTP client handler as inner
        /// handler.
        /// </summary>
        /// <param name="keyId">
        /// An identifier for the key used in <paramref name="algorithm"/>.
        /// </param>
        /// <param name="algorithm">The algorithm used to calculate signatures.</param>
        public SignatureAuthorizationHandler(string keyId, HttpSignatureAlgorithm algorithm)
            : this(keyId, algorithm, new HttpClientHandler())
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureAuthorizationHandler"/> class with
        /// the specified key ID, key and inner handler.
        /// </summary>
        /// <param name="keyId">An identifier for <paramref name="key"/>.</param>
        /// <param name="key">The key used to calculate signatures.</param>
        /// <param name="innerHandler">The inner handler used to process HTTP messages.</param>

        public SignatureAuthorizationHandler(string keyId, byte[] key,
            HttpMessageHandler innerHandler)
            : this(keyId, new HttpSignatureAlgorithm(key), innerHandler)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureAuthorizationHandler"/> class with
        /// the specified key ID, algorithm and inner handler.
        /// </summary>
        /// <param name="keyId">
        /// An identifier for the key used in <paramref name="algorithm"/>.
        /// </param>
        /// <param name="algorithm">The algorithm used to calculate signatures.</param>
        /// <param name="innerHandler">The inner handler used to process HTTP messages.</param>
        public SignatureAuthorizationHandler(string keyId, HttpSignatureAlgorithm algorithm,
            HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            KeyId = keyId;
            Algorithm = algorithm;
        }

        /// <summary>
        /// Gets an identifier for the key used to sign messages.
        /// </summary>
        public string KeyId { get; }

        /// <summary>
        /// Gets or sets the authentication scheme to use when adding the Authorization HTTP request
        /// header.
        /// </summary>
        public string Scheme { get; set; } = "Signature";

        /// <summary>
        /// Gets the algorithm used to calculate signatures.
        /// </summary>
        protected HttpSignatureAlgorithm Algorithm { get; }

        /// <summary>
        /// Add a signature to the HTTP request and sends it to the inner handler.
        /// </summary>
        /// <param name="request">The HTTP request message to sign and send.</param>
        /// <param name="cancellationToken">A cancellation token to cancel operation.</param>
        /// <returns>The task object representing the asynchronous operation.</returns>
        /// <exception cref="ArgumentNullException">
        /// The <paramref name="request">request</paramref> was null.
        /// </exception>
        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            if (request == null)
                throw new ArgumentNullException(nameof(request));

            await request.SignAsync(Algorithm, KeyId).ConfigureAwait(false);
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        }
    }
}