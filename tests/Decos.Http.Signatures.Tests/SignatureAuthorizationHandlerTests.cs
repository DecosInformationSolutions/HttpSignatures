using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using FluentAssertions;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class SignatureAuthorizationHandlerTests
    {
        [Fact]
        public async Task MessageHandlerSignsRequests()
        {
            var algorithm = new HttpSignatureAlgorithm(TestKeyConstants.TestKey, new TestClock());
            var handler = new SignatureAuthorizationHandler(TestKeyConstants.ValidKeyId, algorithm,
                new RequireSignatureHandler());
            using (var client = new HttpClient(handler))
            {
                var response = await client.GetAsync("http://localhost:5000/api/test/1?value=2011-12-20T12:13:21Z");

                response.StatusCode.Should().Be(HttpStatusCode.OK);
            }
        }
    }
}