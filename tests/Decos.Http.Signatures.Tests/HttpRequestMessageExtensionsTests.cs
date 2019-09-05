using System;
using System.Net.Http;
using System.Threading.Tasks;

using FluentAssertions;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class HttpRequestMessageExtensionsTests
    {
        [Fact]
        public async Task SignedRequestContainsValidAuthorizationHeader()
        {
            var algorithm = new HttpSignatureAlgorithm(TestKeyLookup.TestKey, new TestClock());
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri("http://localhost:5000/api/test/1?value=2011-12-20T12:13:21Z")
            };

            await request.SignAsync(algorithm, TestKeyLookup.ValidKeyId);

            request.Headers.Authorization.Should().NotBeNull();
            request.Headers.Authorization.Parameter.Should().NotBeNull();
            var param = SignatureParams.Parse(request.Headers.Authorization.Parameter);
            param.KeyId.Should().Be(TestKeyLookup.ValidKeyId);
            param.Nonce.Should().NotBeNull();
            param.Timestamp.Should().Be(TestClock.TestValue);
            param.Signature.Should().NotBeEmpty();
        }
    }
}