using System;
using System.Threading.Tasks;

using FluentAssertions;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class HttpSignatureClientTests
    {
        private const string TestNonce = "f62c6394-d193-45f1-9703-feaa14678728";
        private const string TestNonce2 = "4175d1e5-93c1-427e-8bab-85f8f1e01fde";

        private static readonly byte[] s_testMessageDefaultSignature = new byte[] {
            169, 151, 63, 27, 156, 37, 194, 103,
            58, 126, 68, 45, 248, 145, 70, 96,
            243, 151, 59, 16, 126, 157, 183, 130,
            198, 28, 126, 109, 50, 76, 111, 129 };

        private static readonly byte[] s_testMessageDefaultSignature2 = new byte[] {
            176, 58, 25, 40, 92, 187, 217, 196,
            42, 12, 207, 48, 87, 97, 107, 57,
            55, 154, 75, 63, 138, 74, 29, 220,
            187, 92, 202, 157, 91, 128, 214, 248 };

        private static readonly DateTimeOffset s_notYetValidTimestamp
            = TestClock.TestValue.AddHours(1.5);

        private static readonly byte[] s_notYetValidSignature = new byte[]
        {
            158, 159, 58, 130, 49, 7, 73, 98,
            14, 211, 190, 253, 86, 140, 88, 175,
            41, 1, 151, 45, 153, 101, 228, 171,
            251, 142, 24, 201, 218, 89, 75, 51
        };

        private static readonly DateTimeOffset s_expiredTimestamp
            = TestClock.TestValue.AddHours(-0.5);

        private static readonly byte[] s_expiredSignature = new byte[]
        {
            131, 53, 133, 85, 199, 77, 20, 178,
            23, 88, 159, 189, 57, 186, 157, 67,
            4, 180, 151, 19, 71, 87, 14, 147,
            161, 168, 88, 243, 254, 88, 31, 149
        };

        private TestClock _testClock;

        [Fact]
        public async Task SignatureClientLoadsKey()
        {
            var client = CreateClient();

            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId);

            signature.Key.Should().Equal(TestKeyLookup.TestKey);
        }

        [Fact]
        public async Task SignatureClientThrowsIfKeyCannotBeFound()
        {
            var client = CreateClient();

            Func<Task> task = () => client.CreateAsync(TestKeyLookup.InvalidKeyId);

            await task.Should().ThrowExactlyAsync<KeyNotFoundException>();
        }

        [Fact]
        public async Task SignatureClientCreatesUsableSignature()
        {
            var client = CreateClient();

            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId);

            var message = CreateTestMessage();
            signature.Hash = signature.Calculate(message, TestNonce, TestClock.TestValue);
            signature.Validate(message, TestNonce, TestClock.TestValue).Should().BeTrue();
        }

        [Fact]
        public async Task SignatureClientValidatesValidSignatureCorrectly()
        {
            var client = CreateClient();
            var message = CreateTestMessage();
            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: s_testMessageDefaultSignature);

            var result = client.Validate(signature,
                message, TestNonce, TestClock.TestValue);

            result.Should().Be(SignatureValidationResult.OK);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfSignatureIsInvalid()
        {
            var client = CreateClient();
            var message = CreateTestMessage();
            var expected = new byte[] { };
            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: expected);

            var result = client.Validate(signature,
                message, TestNonce, TestClock.TestValue);

            result.Should().Be(SignatureValidationResult.Invalid);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfSignatureIsExpired()
        {
            var client = CreateClient();
            var message = CreateTestMessage();
            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: s_expiredSignature);

            var result = client.Validate(signature,
                message, TestNonce, s_expiredTimestamp);

            result.Should().Be(SignatureValidationResult.Expired);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfSignatureIsNotYetValid()
        {
            var client = CreateClient();
            var message = CreateTestMessage();
            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: s_notYetValidSignature);

            var result = client.Validate(signature,
                message, TestNonce, s_notYetValidTimestamp);

            result.Should().Be(SignatureValidationResult.Expired);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfNonceIsReused()
        {
            var client = CreateClient();
            var message = CreateTestMessage();
            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: s_testMessageDefaultSignature);

            client.Validate(signature, message, TestNonce, TestClock.TestValue);
            var result = client.Validate(signature,
                message, TestNonce, TestClock.TestValue);

            result.Should().Be(SignatureValidationResult.Duplicate);
        }

        [Fact]
        public async Task SignatureClientCorrectlyValidatesTwoSignaturesInARow()
        {
            var client = CreateClient();
            var message = CreateTestMessage();
            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: s_testMessageDefaultSignature);
            var signature2 = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: s_testMessageDefaultSignature2);

            client.Validate(signature, message, TestNonce, TestClock.TestValue);
            var result = client.Validate(signature2,
                message, TestNonce2, TestClock.TestValue);

            result.Should().Be(SignatureValidationResult.OK);
        }

        [Fact]
        public async Task SignatureClientCorrectlyValidatesIfNonceIsExpired()
        {
            var client = CreateClient();
            var message = CreateTestMessage();
            var signature = await client.CreateAsync(TestKeyLookup.ValidKeyId,
                signature: s_testMessageDefaultSignature);

            client.Validate(signature, message, TestNonce, TestClock.TestValue);
            _testClock.UtcNow += TimeSpan.FromHours(1);
            var result = client.Validate(signature,
                message, TestNonce, TestClock.TestValue);

            result.Should().Be(SignatureValidationResult.OK);
        }

        private static HttpMessage CreateTestMessage()
        {
            return new HttpMessage
            {
                Method = "GET",
                Uri = "http://localhost:5000/",
                Body = new StringStream("")
            };
        }

        private HttpSignatureClient CreateClient()
        {
            _testClock = new TestClock();
            return new HttpSignatureClient(
                new TestKeyLookup(),
                new MemoryCache(new OptionsWrapper<MemoryCacheOptions>(new MemoryCacheOptions
                {
                    Clock = _testClock
                })),
                new TestClock(),
                new OptionsWrapper<SignatureOptions>(new SignatureOptions()));
        }
    }
}