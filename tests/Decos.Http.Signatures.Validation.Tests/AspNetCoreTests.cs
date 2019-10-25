using System;
using System.Net;
using System.Net.Http;
using System.Threading.Tasks;

using Decos.Http.Signatures.Tests;
using Decos.Http.Signatures.Validation.AspNetCore;

using FluentAssertions;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

using Xunit;
using Xunit.Abstractions;

namespace Decos.Http.Signatures.Validation.Tests
{
    public class AspNetCoreTests
    {
        private const string TestNonce = "f62c6394-d193-45f1-9703-feaa14678728";
        private const string TestMethod = "GET";
        private const string TestUri = "http://localhost:5000/api/test/1?value=2011-12-20T12:13:21Z";
        private const string TestUriEncoded = "http://localhost:5000/api/test/1?value=2011-12-20T12%3a13%3a21Z";

        private static readonly byte[] s_testMessageDefaultSignature = new byte[]
        {
            0xD2, 0x0A, 0xFD, 0x3C, 0xD9, 0x6B, 0xAB, 0x98,
            0x2A, 0x4C, 0xFF, 0x6D, 0x47, 0x0A, 0x76, 0x32,
            0x01, 0x93, 0xD8, 0x5D, 0x31, 0xDB, 0x99, 0xFB,
            0x79, 0x47, 0x4D, 0x12, 0x00, 0x89, 0xC1, 0x38,
        };

        private static readonly DateTimeOffset s_notYetValidTimestamp
            = TestClock.TestValue.AddHours(1.5);

        private static readonly byte[] s_notYetValidSignature = new byte[]
        {
            0x1A, 0xC7, 0x44, 0x1C, 0x92, 0x46, 0x0B, 0x01,
            0xA1, 0x05, 0xDE, 0x08, 0x66, 0x61, 0xF5, 0xC8,
            0xD9, 0x22, 0xB3, 0xDE, 0xCC, 0x4A, 0xC3, 0x98,
            0x1E, 0xC1, 0x8B, 0x93, 0x6A, 0x30, 0x9C, 0xE7,
        };

        private static readonly DateTimeOffset s_expiredTimestamp
                = TestClock.TestValue.AddHours(-0.5);

        private static readonly byte[] s_expiredSignature = new byte[]
        {
            0x83, 0x35, 0x85, 0x55, 0xC7, 0x4D, 0x14, 0xB2,
            0x17, 0x58, 0x9F, 0xBD, 0x39, 0xBA, 0x9D, 0x43,
            0x04, 0xB4, 0x97, 0x13, 0x47, 0x57, 0x0E, 0x93,
            0xA1, 0xA8, 0x58, 0xF3, 0xFE, 0x58, 0x1F, 0x95,
        };

        private TestClock _testClock;
        private readonly ITestOutputHelper _outputHelper;

        public AspNetCoreTests(ITestOutputHelper outputHelper)
        {
            _outputHelper = outputHelper;
        }

        [Fact]
        public async Task AuthenticationHandlerIgnoresUnauthenticatedRequests()
        {
            var server = CreateTestServer();

            var response = await SendAsync(server, TestMethod, TestUri);

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task AuthenticationHandlerIgnoresRequestsWithDifferentAuthentication()
        {
            var server = CreateTestServer();

            var response = await SendOtherAsync(server);

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task AuthenticationHandlerIssuesChallenge()
        {
            var server = CreateTestServer();

            var response = await SendAsync(server, TestMethod, TestUri);

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
            response.Headers.WwwAuthenticate.Should().NotBeEmpty();
        }

        [Fact]
        public async Task AuthenticationHandlerAcceptsValidRequests()
        {
            var server = CreateTestServer();

            var response = await SendAsync(server, TestMethod, TestUri, GetTestParams());

            response.StatusCode.Should().Be(HttpStatusCode.OK);
        }

        [Fact]
        public async Task AuthenticationHandlerSetsUserNameToKeyId()
        {
            var server = CreateTestServer();

            var response = await SendAsync(server, TestMethod, TestUri, GetTestParams());

            var body = await response.Content.ReadAsStringAsync();
            body.Should().Be(TestKeyLookup.ValidKeyId);
        }

        [Fact]
        public async Task AuthenticationHandlerIgnoresInvalidSignatures()
        {
            var server = CreateTestServer();

            var response = await SendAsync(server, TestMethod, TestUri, GetInvalidTestParams());

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task AuthenticationHandlerIgnoresExpiredSignatures()
        {
            var server = CreateTestServer();

            var response = await SendAsync(server, TestMethod, TestUri, GetExpiredTestParams());

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task AuthenticationHandlerIgnoresNotYetValidSignatures()
        {
            var server = CreateTestServer();

            var response = await SendAsync(server, TestMethod, TestUri, GetNotYetValidTestParams());

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        [Fact]
        public async Task AuthenticationHandlerIgnoresDuplicateSignatures()
        {
            var server = CreateTestServer();

            await SendAsync(server, TestMethod, TestUri, GetTestParams());
            var response = await SendAsync(server, TestMethod, TestUri, GetTestParams());

            response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        }

        private HttpSignature GetTestParams()
        {
            return new HttpSignature
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce,
                Timestamp = TestClock.TestValue,
                Hash = s_testMessageDefaultSignature
            };
        }

        private HttpSignature GetInvalidTestParams()
        {
            return new HttpSignature
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce,
                Timestamp = TestClock.TestValue,
                Hash = new byte[0]
            };
        }

        private HttpSignature GetExpiredTestParams()
        {
            return new HttpSignature
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce,
                Timestamp = s_expiredTimestamp,
                Hash = s_expiredSignature
            };
        }

        private HttpSignature GetNotYetValidTestParams()
        {
            return new HttpSignature
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce,
                Timestamp = s_notYetValidTimestamp,
                Hash = s_notYetValidSignature
            };
        }

        private HttpSignatureValidator CreateValidator()
        {
            _testClock = new TestClock();
            return new HttpSignatureValidator(
                new TestKeyLookup(),
                new MemoryCache(new OptionsWrapper<MemoryCacheOptions>(new MemoryCacheOptions
                {
                    Clock = _testClock
                })),
                new TestClock(),
                new OptionsWrapper<SignatureOptions>(new SignatureOptions()),
                new LoggerFactory().AddXUnit(_outputHelper, LogLevel.Trace).CreateLogger<HttpSignatureValidator>());
        }

        private TestServer CreateTestServer(bool requireAuthorization = true)
        {
            var hostBuilder = new WebHostBuilder()
                .Configure(app =>
                {
                    app.UseAuthentication();
                    app.Use(async (context, next) =>
                    {
                        if (requireAuthorization && !context.User.Identity.IsAuthenticated)
                        {
                            await context.ChallengeAsync();
                            return;
                        }

                        if (context.User.Identity.IsAuthenticated)
                            await context.Response.WriteAsync(context.User.Identity.Name);
                        return;
                    });
                })
                .ConfigureServices(services =>
                {
                    services.AddSingleton(CreateValidator());
                    services.AddSingleton<ISystemClock>(_testClock);
                    services.AddAuthentication(SignatureDefaults.AuthenticationScheme)
                        .AddSignature();
                });

            return new TestServer(hostBuilder);
        }

        private async Task<HttpResponseMessage> SendAsync(TestServer server, string method, string uri, HttpSignature signature = null)
        {
            var client = server.CreateClient();
            var request = new HttpRequestMessage
            {
                Method = new HttpMethod(method),
                RequestUri = new Uri(uri)
            };

            if (signature != null)
            {
                request.Headers.Add("Authorization", "Signature " + signature.ToString());
            }
            return await client.SendAsync(request);
        }

        private async Task<HttpResponseMessage> SendOtherAsync(TestServer server)
        {
            var client = server.CreateClient();
            var request = new HttpRequestMessage
            {
                Method = new HttpMethod(TestMethod),
                RequestUri = new Uri(TestUri)
            };

            request.Headers.Add("Authorization", "Bearer " + Convert.ToBase64String(Guid.NewGuid().ToByteArray()));
            return await client.SendAsync(request);
        }
    }
}