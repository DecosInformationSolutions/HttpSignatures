using System;
using System.IO;

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
            Action task = () => new HttpSignatureAlgorithm(new byte[0]);
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public void SignatureCalculationRequiresMethod()
        {
            var signature = GetTestAlgorithm();

            Action task = () => signature.CalculateHash(null, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            task.Should().ThrowExactly<ArgumentNullException>();
        }

        [Fact]
        public void SignatureCalculationRequiresUri()
        {
            var signature = GetTestAlgorithm();

            Action task = () => signature.CalculateHash(TestMethod, null, new StringStream(""), TestNonce, TestClock.TestValue);
            task.Should().ThrowExactly<ArgumentNullException>();
        }

        [Fact]
        public void SignatureCalculationRequiresNonce()
        {
            var signature = GetTestAlgorithm();

            Action task = () => signature.CalculateHash(TestMethod, TestUri, new StringStream(""), null, TestClock.TestValue);
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public void SignatureCalculationRequiresTimestamp()
        {
            var signature = GetTestAlgorithm();

            Action task = () => signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, default);
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public void SignatureCalculationRewindsBodyStream()
        {
            var signature = GetTestAlgorithm();
            var stream = new StringStream(new string(' ', 100));

            try
            {
                signature.CalculateHash(TestMethod, TestUri, stream, TestNonce, TestClock.TestValue);
            }
            catch (NotImplementedException) { }

            stream.Position.Should().Be(0);
        }

        [Fact]
        public void SignatureCalculationResetsBodyStreamToOriginalPosition()
        {
            const int Offset = 50;
            var signature = GetTestAlgorithm();
            var stream = new StringStream(new string(' ', 100));
            stream.Seek(Offset, SeekOrigin.Begin);

            try
            {
                signature.CalculateHash(TestMethod, TestUri, stream, TestNonce, TestClock.TestValue);
            }
            catch (NotImplementedException) { }

            stream.Position.Should().Be(Offset);
        }

        [Fact]
        public void CalculatedSignatureIsConsistent()
        {
            var signature = GetTestAlgorithm();
            var expected = new byte[] {
                105, 165, 255, 192, 146, 98, 37, 143,
                37, 194, 192, 246, 115, 7, 11, 253,
                19, 145, 211, 31, 241, 77, 58, 25,
                6, 41, 19, 0, 223, 136, 62, 80 };

            var hash = signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            hash.Should().Equal(expected);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentHttpMethods()
        {
            var signature = GetTestAlgorithm();

            var hash1 = signature.CalculateHash("GET", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = signature.CalculateHash("POST", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsTheSameWhenHttpMethodCasingIsDifferent()
        {
            var signature = GetTestAlgorithm();

            var hash1 = signature.CalculateHash("GET", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = signature.CalculateHash("get", TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            hash1.Should().Equal(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentUrls()
        {
            var signature = GetTestAlgorithm();

            var hash1 = signature.CalculateHash(TestMethod, "", new StringStream("http://localhost:5000/?test=1"), TestNonce, TestClock.TestValue);
            var hash2 = signature.CalculateHash(TestMethod, "", new StringStream("http://localhost:5000/?test=2"), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentNonces()
        {
            var signature = GetTestAlgorithm();

            var hash1 = signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce2, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentTimestamps()
        {
            var signature = GetTestAlgorithm();

            var hash1 = signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue.AddMinutes(5));
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsTheSameWhenTimestampsDifferOnlyInMilliseconds()
        {
            var signature = GetTestAlgorithm();

            var hash1 = signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = signature.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue.AddMilliseconds(200));
            hash1.Should().Equal(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentBodies()
        {
            var signature = GetTestAlgorithm();

            var hash1 = signature.CalculateHash(TestMethod, TestUri, new StringStream("{ \"test\": 1}"), TestNonce, TestClock.TestValue);
            var hash2 = signature.CalculateHash(TestMethod, TestUri, new StringStream("{ \"test\": 2}"), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentKeys()
        {
            var signature1 = new HttpSignatureAlgorithm(TestKeyLookup.TestKey);
            var signature2 = new HttpSignatureAlgorithm(TestKeyLookup.TestKey2);

            var hash1 = signature1.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            var hash2 = signature2.CalculateHash(TestMethod, TestUri, new StringStream(""), TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        private HttpSignatureAlgorithm GetTestAlgorithm()
        {
            return new HttpSignatureAlgorithm(TestKeyLookup.TestKey);
        }
    }
}