using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;

namespace Decos.Http.Signatures
{
    public class SignatureAuthorizationHandler : DelegatingHandler
    {
        public SignatureAuthorizationHandler(string keyId, byte[] key)
            : this(keyId, new HttpSignatureAlgorithm(key))
        {
        }

        public SignatureAuthorizationHandler(string keyId, HttpSignatureAlgorithm algorithm)
            : this(keyId, algorithm, new HttpClientHandler())
        {
        }

        public SignatureAuthorizationHandler(string keyId, byte[] key,
            HttpMessageHandler innerHandler)
            : this(keyId, new HttpSignatureAlgorithm(key), innerHandler)
        {
        }

        public SignatureAuthorizationHandler(string keyId, HttpSignatureAlgorithm algorithm,
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