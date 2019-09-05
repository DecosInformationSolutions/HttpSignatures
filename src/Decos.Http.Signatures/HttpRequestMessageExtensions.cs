using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Provides a set of static methods for calculating and validating signatures on an HTTP request
    /// message.
    /// </summary>
    public static class HttpRequestMessageExtensions
    {
        public static async Task SignAsync(this HttpRequestMessage request,
            HttpSignatureAlgorithm signatureAlgorithm,
            string keyId,
            string scheme = "Signature")
        {
            var stream = await request.Content.ReadAsStreamAsync();
            var hash = signatureAlgorithm.CalculateHash(request.Method.ToString(),
                request.RequestUri.OriginalString, stream, out var nonce, out var timestamp);

            var param = new SignatureParams
            {
                KeyId = keyId,
                Nonce = nonce,
                Timestamp = timestamp,
                Signature = hash
            };

            request.Headers.Authorization = new AuthenticationHeaderValue(scheme,
                param.ToString());
        }
    }
}