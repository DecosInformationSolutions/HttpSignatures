using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;

namespace Decos.Http.Signatures.Tests
{
    /// <summary>
    /// Represents an HTTP message handler that asserts requests have a Signature authorization
    /// header and returns 200 OK responses.
    /// </summary>
    internal class RequireSignatureHandler : HttpMessageHandler
    {
        protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            request.Headers.Authorization.Should().NotBeNull();
            request.Headers.Authorization.Parameter.Should().NotBeNull();
            var param = HttpSignature.Parse(request.Headers.Authorization.Parameter);
            param.KeyId.Should().NotBeNull();
            param.Nonce.Should().NotBeNull();
            param.Hash.Should().NotBeEmpty();

            return Task.FromResult(new HttpResponseMessage
            {
                StatusCode = HttpStatusCode.OK,
                RequestMessage = request
            });
        }
    }
}