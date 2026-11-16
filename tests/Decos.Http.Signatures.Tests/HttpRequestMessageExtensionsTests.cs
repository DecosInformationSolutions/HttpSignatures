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
            var algorithm = new HttpSignatureAlgorithm(TestKeyConstants.TestKey, new TestClock());
            var request = new HttpRequestMessage
            {
                Method = HttpMethod.Get,
                RequestUri = new Uri("http://localhost:5000/api/test/1?value=2011-12-20T12:13:21Z")
            };

            await request.SignAsync(algorithm, TestKeyConstants.ValidKeyId);

            request.Headers.Authorization.Should().NotBeNull();
            request.Headers.Authorization.Parameter.Should().NotBeNull();
            var param = HttpSignature.Parse(request.Headers.Authorization.Parameter);
            param.KeyId.Should().Be(TestKeyConstants.ValidKeyId);
            param.Nonce.Should().NotBeNull();
            param.Timestamp.Should().Be(TestClock.TestValue);
            param.Hash.Should().NotBeEmpty();
        }

        [Fact]
        public async Task SigningRelativeUriThrows()
        {
            var algorithm = new HttpSignatureAlgorithm(TestKeyConstants.TestKey, new TestClock());
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/1");

            Func<Task> task = async () => await request.SignAsync(algorithm, TestKeyConstants.ValidKeyId);

            await task.Should().ThrowExactlyAsync<InvalidOperationException>();
        }

        [Fact]
        public async Task SigningWithoutUriThrows()
        {
            var algorithm = new HttpSignatureAlgorithm(TestKeyConstants.TestKey, new TestClock());
            var request = new HttpRequestMessage { Method = HttpMethod.Get, RequestUri = null };

            Func<Task> task = async () => await request.SignAsync(algorithm, TestKeyConstants.ValidKeyId);

            await task.Should().ThrowExactlyAsync<InvalidOperationException>();
        }

        [Fact]
        public async Task SigningRelativeUriDoesNotSetAuthorizationHeader()
        {
            var algorithm = new HttpSignatureAlgorithm(TestKeyConstants.TestKey, new TestClock());
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/test/1");

            try
            {
                await request.SignAsync(algorithm, TestKeyConstants.ValidKeyId);
            }
            catch (InvalidOperationException)
            {
            }

            request.Headers.Authorization.Should().BeNull();
        }
    }
}