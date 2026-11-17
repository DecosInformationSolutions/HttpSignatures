using System;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Http.Features;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    /// <summary>
    /// Provides signature extensions on an ASP.NET Core <see cref="HttpRequest"/> object.
    /// </summary>
    public static class HttpRequestExtensions
    {
        /// <summary>
        /// Determines whether the signature is valid for the specified message.
        /// </summary>
        /// <param name="validator">Used to validate the signature.</param>
        /// <param name="request">The request message that contains the signature.</param>
        /// <param name="signature">The signature to validate.</param>
        /// <returns>
        /// A <see cref="SignatureValidationResult"/> that represents the result of the validation.
        /// </returns>
        public static async Task<SignatureValidationResult> ValidateAsync(
            this HttpSignatureValidator validator, HttpRequest request,
            HttpSignature signature)
        {
            // Allow to read the request body multiple times
            request.EnableBuffering();

            // Both candidates below include the scheme and host. A signature that covers only the
            // path is not bound to any host, so it would authenticate against any host and against
            // any other service sharing the same key.
            if (!request.Host.HasValue)
            {
                // Without a host there is nothing to bind the signature to.
                return SignatureValidationResult.Invalid;
            }

            var authority = request.Scheme + "://" + request.Host.ToUriComponent();

            // First we try the raw request target, which preserves the exact encoding the client
            // used. GetEncodedUrl() re-encodes, and does not always round-trip what was signed.
            var requestFeature = request.HttpContext.Features.Get<IHttpRequestFeature>();
            if (!string.IsNullOrEmpty(requestFeature?.RawTarget))
            {
                var result = await validator.ValidateAsync(signature,
                    request.Method,
                    authority + requestFeature.RawTarget,
                    request.Body).ConfigureAwait(false);

                // If the signature is OK, we're done. If it's Expired or Duplicate, there's no point
                // in checking again.
                if (result != SignatureValidationResult.Invalid)
                    return result;
            }

            return await validator.ValidateAsync(signature,
                request.Method,
                request.GetEncodedUrl(),
                request.Body).ConfigureAwait(false);
        }
    }
}