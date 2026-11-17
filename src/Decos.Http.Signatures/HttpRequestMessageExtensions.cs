using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Provides a set of static methods for signing a <see cref="HttpRequestMessage"/>.
    /// </summary>
    public static class HttpRequestMessageExtensions
    {
        /// <summary>
        /// Adds a signature to the HTTP message, using the specified algorithm and key.
        /// </summary>
        /// <param name="request">The HTTP request message to sign.</param>
        /// <param name="signatureAlgorithm">
        /// A signature algorithm used to calculate a signature.
        /// </param>
        /// <param name="keyId">
        /// An identifier for the key used in <paramref name="signatureAlgorithm"/>.
        /// </param>
        /// <param name="scheme">
        /// The authorization header scheme to use when signing the request.
        /// </param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        /// <exception cref="InvalidOperationException">
        /// <paramref name="request"/> has no request URI, or its request URI is relative. A
        /// signature is bound to the scheme and host it was created for, so a relative URI cannot
        /// be signed.
        /// </exception>
        public static async Task SignAsync(this HttpRequestMessage request,
            HttpSignatureAlgorithm signatureAlgorithm,
            string keyId,
            string scheme = "Signature")
        {
            if (request.RequestUri is null || !request.RequestUri.IsAbsoluteUri)
            {
                // A signature over a relative URI is not bound to any host, so it would authenticate
                // against any host and against any other service sharing the same key. Validators
                // reject such signatures, so fail here rather than produce one that cannot be used.
                throw new InvalidOperationException(
                    "The request URI must be an absolute URI in order to sign the request. Specify "
                    + "an absolute URI, or use an HttpClient with a BaseAddress so the request URI "
                    + "is resolved before the request is signed.");
            }

            var stream = request.Content != null ? await request.Content.ReadAsStreamAsync().ConfigureAwait(false) : null;
            var (hash, nonce, timestamp) = await signatureAlgorithm.CalculateHashAsync(request.Method.ToString(),
                request.RequestUri.OriginalString, stream, default);

            var param = new HttpSignature
            {
                KeyId = keyId,
                Nonce = nonce,
                Timestamp = timestamp,
                Hash = hash
            };

            request.Headers.Authorization = new AuthenticationHeaderValue(scheme,
                param.ToString());
        }
    }
}