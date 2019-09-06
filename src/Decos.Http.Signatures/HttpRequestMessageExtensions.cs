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
        public static async Task SignAsync(this HttpRequestMessage request,
            HttpSignatureAlgorithm signatureAlgorithm,
            string keyId,
            string scheme = "Signature")
        {
            var stream = request.Content != null ? await request.Content.ReadAsStreamAsync() : null;
            var hash = signatureAlgorithm.CalculateHash(request.Method.ToString(),
                request.RequestUri.OriginalString, stream, out var nonce, out var timestamp);

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