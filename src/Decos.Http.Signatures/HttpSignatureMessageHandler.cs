using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Decos.Http.Signatures
{
    public class HttpSignatureMessageHandler : DelegatingHandler
    {
        public HttpSignatureMessageHandler(string keyId, byte[] key)
            : this(keyId, new HttpSignatureAlgorithm(key))
        {
        }

        public HttpSignatureMessageHandler(string keyId, HttpSignatureAlgorithm algorithm)
        {
            KeyId = keyId;
            Algorithm = algorithm;
        }

        public HttpSignatureMessageHandler(string keyId, byte[] key,
            HttpMessageHandler innerHandler)
            : this(keyId, new HttpSignatureAlgorithm(key), innerHandler)
        {
        }

        public HttpSignatureMessageHandler(string keyId, HttpSignatureAlgorithm algorithm,
            HttpMessageHandler innerHandler)
            : base(innerHandler)
        {
            KeyId = keyId;
            Algorithm = algorithm;
        }

        public string KeyId { get; }

        public string Scheme { get; set; } = "Signature";

        protected HttpSignatureAlgorithm Algorithm { get; }

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            await request.SignAsync(Algorithm, KeyId);
            return await base.SendAsync(request, cancellationToken);
        }
    }
}