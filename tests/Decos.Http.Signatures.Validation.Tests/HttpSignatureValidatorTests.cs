using System;
using System.Threading.Tasks;

using Decos.Http.Signatures.Tests;
using Decos.Http.Signatures.Validation.AspNetCore;

using FluentAssertions;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Internal;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

using Xunit;

namespace Decos.Http.Signatures.Validation.Tests
{
    public class HttpSignatureValidatorTests
    {
        private const string TestNonce = "f62c6394-d193-45f1-9703-feaa14678728";
        private const string TestNonce2 = "4175d1e5-93c1-427e-8bab-85f8f1e01fde";
        private const string TestMethod = "GET";
        private const string TestUri = "http://localhost:5000/api/test/1?value=2011-12-20T12:13:21Z";

        private static readonly byte[] s_testMessageDefaultSignature = new byte[]
        {
            0xD2, 0x0A, 0xFD, 0x3C, 0xD9, 0x6B, 0xAB, 0x98,
            0x2A, 0x4C, 0xFF, 0x6D, 0x47, 0x0A, 0x76, 0x32,
            0x01, 0x93, 0xD8, 0x5D, 0x31, 0xDB, 0x99, 0xFB,
            0x79, 0x47, 0x4D, 0x12, 0x00, 0x89, 0xC1, 0x38,
        };

        private static readonly byte[] s_testMessageDefaultSignature2 = new byte[]
        {
            0x8A, 0xA6, 0xDB, 0x52, 0x49, 0x6B, 0x14, 0xDF,
            0xC2, 0x80, 0x41, 0xA3, 0x9B, 0x05, 0x46, 0x0F,
            0xE5, 0xDD, 0x9D, 0xE2, 0x95, 0x52, 0x8C, 0x29,
            0x94, 0xAE, 0x8B, 0x1A, 0xC8, 0x06, 0x28, 0x77,
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

        [Fact]
        public async Task SignatureClientThrowsIfKeyCannotBeFound()
        {
            var client = CreateValidator();
            var signature = GetTestParamsWithInvalidKey();

            Func<Task> task = () => client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));

            await task.Should().ThrowExactlyAsync<KeyNotFoundException>();
        }

        [Fact]
        public async Task SignatureClientCorrectlyValidatesIfSignatureIsValid()
        {
            var client = CreateValidator();
            var signature = GetTestParams();

            var result = await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.OK);
        }

        [Fact]
        public async Task SignatureClientCorrectlyValidatesIfTimestampIsOffByLessThanASecond()
        {
            var client = CreateValidator();
            var signature = GetTestParams();
            signature.Timestamp += TimeSpan.FromMilliseconds(500);

            var result = await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.OK);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfSignatureIsInvalid()
        {
            var client = CreateValidator();
            var signature = GetTestParams();
            signature.Nonce = TestNonce2;

            var result = await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.Invalid);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfTimestampIsIncorrect()
        {
            var client = CreateValidator();
            var signature = GetTestParams();
            signature.Timestamp += TimeSpan.FromSeconds(5);

            var result = await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.Invalid);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfSignatureIsExpired()
        {
            var client = CreateValidator();
            var signature = GetExpiredTestParams();

            var result = await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.Expired);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfSignatureIsNotYetValid()
        {
            var client = CreateValidator();
            var signature = GetNotYetValidTestParams();

            var result = await client.ValidateAsync(signature,
                TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.Expired);
        }

        [Fact]
        public async Task SignatureClientFailsValidationIfNonceIsReused()
        {
            var client = CreateValidator();
            var signature = GetTestParams();

            await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));
            var result = await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.Duplicate);
        }

        [Fact]
        public async Task SignatureClientCorrectlyValidatesTwoSignaturesInARow()
        {
            var client = CreateValidator();
            var signature = GetTestParams();
            var signature2 = GetTestParams2();

            await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));
            var result = await client.ValidateAsync(signature2,
                TestMethod, TestUri, new StringStream(""));

            result.Should().Be(SignatureValidationResult.OK);
        }

        [Fact]
        public async Task SignatureClientCorrectlyValidatesIfNonceIsExpired()
        {
            var client = CreateValidator();

            var signature = GetTestParams();
            var result = await client.ValidateAsync(signature, TestMethod, TestUri, new StringStream(""));
            result.Should().Be(SignatureValidationResult.OK);

            _testClock.UtcNow += TimeSpan.FromHours(1);
            var signature2 = GetTestParams();
            var result2 = await client.ValidateAsync(signature2, TestMethod,
                TestUri, new StringStream(""));

            result2.Should().Be(SignatureValidationResult.OK);
        }

        private SignatureParams GetTestParams()
        {
            return new SignatureParams
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce,
                Timestamp = TestClock.TestValue,
                Signature = s_testMessageDefaultSignature
            };
        }

        private SignatureParams GetTestParams2()
        {
            return new SignatureParams
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce2,
                Timestamp = TestClock.TestValue,
                Signature = s_testMessageDefaultSignature2
            };
        }

        private SignatureParams GetExpiredTestParams()
        {
            return new SignatureParams
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce,
                Timestamp = s_expiredTimestamp,
                Signature = s_expiredSignature
            };
        }

        private SignatureParams GetNotYetValidTestParams()
        {
            return new SignatureParams
            {
                KeyId = TestKeyLookup.ValidKeyId,
                Nonce = TestNonce,
                Timestamp = s_notYetValidTimestamp,
                Signature = s_notYetValidSignature
            };
        }

        private SignatureParams GetTestParamsWithInvalidKey()
        {
            return new SignatureParams
            {
                KeyId = TestKeyLookup.InvalidKeyId,
                Nonce = TestNonce,
                Timestamp = TestClock.TestValue,
                Signature = s_testMessageDefaultSignature
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
                new OptionsWrapper<SignatureOptions>(new SignatureOptions()));
        }
    }
}