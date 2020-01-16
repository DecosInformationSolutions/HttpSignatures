using System;
using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using FluentAssertions;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class HttpSignatureAlgorithmTests
    {
        private const string TestNonce = "a1d76f81-de54-498c-8ccf-7ed9e069596a";
        private const string TestNonce2 = "bd100488-83af-4219-97a9-02e2ddeaf7cc";
        private const string TestMethod = "GET";
        private const string TestUri = "http://localhost:5000/api/test/1?value=2011-12-20T12:13:21Z";

        [Fact]
        public void SignatureCalculationRequiresKey()
        {
            Action task = () => new HttpSignatureAlgorithm(null);
            task.Should().ThrowExactly<ArgumentNullException>();
        }

        [Fact]
        public void SignatureCalculationRequiresNonEmptyKey()
        {
            Action task = () => new HttpSignatureAlgorithm(Array.Empty<byte>());
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public void SignatureCalculationRequiresMethod()
        {
            var algorithm = GetTestAlgorithm();

            Func<Task> task = async () => await algorithm.CalculateHashAsync(null, TestUri, new StringStream(""), TestNonce, TestClock.TestValue, default);
            task.Should().ThrowExactly<ArgumentNullException>();
        }

        [Fact]
        public void SignatureCalculationRequiresUri()
        {
            var algorithm = GetTestAlgorithm();

            Func<Task> task = async () => await algorithm.CalculateHashAsync(TestMethod, null, new StringStream(""), TestNonce, TestClock.TestValue, default);
            task.Should().ThrowExactly<ArgumentNullException>();
        }

        [Fact]
        public void SignatureCalculationRequiresNonce()
        {
            var algorithm = GetTestAlgorithm();

            Func<Task> task = async () => await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), null, TestClock.TestValue, default);
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public void SignatureCalculationRequiresTimestamp()
        {
            var algorithm = GetTestAlgorithm();

            Func<Task> task = async () => await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, default, default);
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public async Task SignatureCalculationRewindsBodyStream()
        {
            var algorithm = GetTestAlgorithm();
            var stream = new StringStream(new string(' ', 100));

            try
            {
                await algorithm.CalculateHashAsync(TestMethod, TestUri, stream, TestNonce, TestClock.TestValue, default);
            }
            catch (NotImplementedException) { }

            stream.Position.Should().Be(0);
        }

        [Fact]
        public async Task SignatureCalculationResetsBodyStreamToOriginalPosition()
        {
            const int Offset = 50;
            var algorithm = GetTestAlgorithm();
            var stream = new StringStream(new string(' ', 100));
            stream.Seek(Offset, SeekOrigin.Begin);

            try
            {
                await algorithm.CalculateHashAsync(TestMethod, TestUri, stream, TestNonce, TestClock.TestValue, default);
            }
            catch (NotImplementedException) { }

            stream.Position.Should().Be(Offset);
        }

        [Fact]
        public async Task CalculatedSignatureIsConsistent()
        {
            var algorithm = GetTestAlgorithm();
            var expected = new byte[] {
                0x69, 0xA5, 0xFF, 0xC0, 0x92, 0x62, 0x25, 0x8F,
                0x25, 0xC2, 0xC0, 0xF6, 0x73, 0x07, 0x0B, 0xFD,
                0x13, 0x91, 0xD3, 0x1F, 0xF1, 0x4D, 0x3A, 0x19,
                0x06, 0x29, 0x13, 0x00, 0xDF, 0x88, 0x3E, 0x50 };

            var hash = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue, default);
            hash.Should().Equal(expected);
        }

        [Fact]
        public void HmacIsConsistent()
        {
            var expected = new byte[] {
                0x69, 0xA5, 0xFF, 0xC0, 0x92, 0x62, 0x25, 0x8F,
                0x25, 0xC2, 0xC0, 0xF6, 0x73, 0x07, 0x0B, 0xFD,
                0x13, 0x91, 0xD3, 0x1F, 0xF1, 0x4D, 0x3A, 0x19,
                0x06, 0x29, 0x13, 0x00, 0xDF, 0x88, 0x3E, 0x50 };

            using (var hmac = new HMACSHA256(TestKeyConstants.TestKey))
            {
                var hash = hmac.ComputeHash(new byte[] {
                    0x47, 0x45, 0x54, 0x20, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x6C, 0x6F, 0x63, 0x61, 0x6C,
                    0x68, 0x6F, 0x73, 0x74, 0x3A, 0x35, 0x30, 0x30, 0x30, 0x2F, 0x61, 0x70, 0x69, 0x2F, 0x74, 0x65,
                    0x73, 0x74, 0x2F, 0x31, 0x3F, 0x76, 0x61, 0x6C, 0x75, 0x65, 0x3D, 0x32, 0x30, 0x31, 0x31, 0x2D,
                    0x31, 0x32, 0x2D, 0x32, 0x30, 0x54, 0x31, 0x32, 0x3A, 0x31, 0x33, 0x3A, 0x32, 0x31, 0x5A, 0x0D,
                    0x0A, 0x61, 0x31, 0x64, 0x37, 0x36, 0x66, 0x38, 0x31, 0x2D, 0x64, 0x65, 0x35, 0x34, 0x2D, 0x34,
                    0x39, 0x38, 0x63, 0x2D, 0x38, 0x63, 0x63, 0x66, 0x2D, 0x37, 0x65, 0x64, 0x39, 0x65, 0x30, 0x36,
                    0x39, 0x35, 0x39, 0x36, 0x61, 0x0D, 0x0A, 0x31, 0x33, 0x32, 0x34, 0x33, 0x38, 0x33, 0x32, 0x30,
                    0x31, 0x0D, 0x0A, 0x34, 0x37, 0x44, 0x45, 0x51, 0x70, 0x6A, 0x38, 0x48, 0x42, 0x53, 0x61, 0x2B,
                    0x2F, 0x54, 0x49, 0x6D, 0x57, 0x2B, 0x35, 0x4A, 0x43, 0x65, 0x75, 0x51, 0x65, 0x52, 0x6B, 0x6D,
                    0x35, 0x4E, 0x4D, 0x70, 0x4A, 0x57, 0x5A, 0x47, 0x33, 0x68, 0x53, 0x75, 0x46, 0x55, 0x3D, 0x0D,
                    0x0A });
                hash.Should().Equal(expected);
            }
        }

        [Fact]
        public void Sha256isConsistenet()
        {
            var expected = new byte[]{
                0xE3, 0xB0, 0xC4, 0x42, 0x98, 0xFC, 0x1C, 0x14,
                0x9A, 0xFB, 0xF4, 0xC8, 0x99, 0x6F, 0xB9, 0x24,
                0x27, 0xAE, 0x41, 0xE4, 0x64, 0x9B, 0x93, 0x4C,
                0xA4, 0x95, 0x99, 0x1B, 0x78, 0x52, 0xB8, 0x55 };

            using (var sha = SHA256.Create())
            {
                var hash = sha.ComputeHash(new byte[0]);
                hash.Should().Equal(expected);
            }
        }

        [Fact]
        public async Task CalculatedSignatureIsDifferentForDifferentHttpMethods()
        {
            var algorithm = GetTestAlgorithm();

            var hash1 = await algorithm.CalculateHashAsync("GET", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm.CalculateHashAsync("POST", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public async Task CalculatedSignatureIsTheSameWhenHttpMethodCasingIsDifferent()
        {
            var algorithm = GetTestAlgorithm();

            var hash1 = await algorithm.CalculateHashAsync("GET", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm.CalculateHashAsync("get", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            hash1.Should().Equal(hash2);
        }

        [Fact]
        public async Task CalculatedSignatureIsDifferentForDifferentUrls()
        {
            var algorithm = GetTestAlgorithm();

            var hash1 = await algorithm.CalculateHashAsync(TestMethod, "", new StringStream("http://localhost:5000/?test=1"), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm.CalculateHashAsync(TestMethod, "", new StringStream("http://localhost:5000/?test=2"), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public async Task CalculatedSignatureIsDifferentForDifferentNonces()
        {
            var algorithm = GetTestAlgorithm();

            var hash1 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce2, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public async Task CalculatedSignatureIsDifferentForDifferentTimestamps()
        {
            var algorithm = GetTestAlgorithm();

            var hash1 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue.AddMinutes(5));
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public async Task CalculatedSignatureIsTheSameWhenTimestampsDifferOnlyInMilliseconds()
        {
            var algorithm = GetTestAlgorithm();

            var hash1 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue.AddMilliseconds(200));
            hash1.Should().Equal(hash2);
        }

        [Fact]
        public async Task CalculatedSignatureIsDifferentForDifferentBodies()
        {
            var algorithm = GetTestAlgorithm();

            var hash1 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream("{ \"test\": 1}"), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm.CalculateHashAsync(TestMethod, TestUri, new StringStream("{ \"test\": 2}"), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public async Task CalculatedSignatureIsDifferentForDifferentKeys()
        {
            var algorithm1 = new HttpSignatureAlgorithm(TestKeyConstants.TestKey);
            var algorithm2 = new HttpSignatureAlgorithm(TestKeyConstants.TestKey2);

            var hash1 = await algorithm1.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = await algorithm2.CalculateHashAsync(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        private HttpSignatureAlgorithm GetTestAlgorithm()
        {
            return new HttpSignatureAlgorithm(TestKeyConstants.TestKey);
        }
    }
}