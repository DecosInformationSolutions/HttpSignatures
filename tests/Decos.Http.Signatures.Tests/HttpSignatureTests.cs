using System;
using System.IO;

using FluentAssertions;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class HttpSignatureTests
    {
        private const string TestNonce = "a1d76f81-de54-498c-8ccf-7ed9e069596a";
        private const string TestNonce2 = "bd100488-83af-4219-97a9-02e2ddeaf7cc";

        [Fact]
        public void SignatureCalculationRequiresKey()
        {
            var signature = GetTestSignature();
            signature.Key = null;

            Action task = () => signature.Calculate(GetTestMessage(), TestNonce, TestClock.TestValue);
            task.Should().ThrowExactly<InvalidOperationException>();
        }

        [Fact]
        public void SignatureCalculationRequiresNonEmptyKey()
        {
            var signature = GetTestSignature();
            signature.Key = new byte[0];

            Action task = () => signature.Calculate(GetTestMessage(), TestNonce, TestClock.TestValue);
            task.Should().ThrowExactly<InvalidOperationException>();
        }

        [Fact]
        public void SignatureCalculationRequiresAlgorithm()
        {
            var signature = GetTestSignature();
            signature.Algorithm = "";

            Action task = () => signature.Calculate(GetTestMessage(), TestNonce, TestClock.TestValue);
            task.Should().ThrowExactly<InvalidOperationException>();
        }

        [Fact]
        public void SignatureCalculationRequiresContentAlgorithm()
        {
            var signature = GetTestSignature();
            signature.ContentAlgorithm = "";

            Action task = () => signature.Calculate(GetTestMessage(), TestNonce, TestClock.TestValue);
            task.Should().ThrowExactly<InvalidOperationException>();
        }

        [Fact]
        public void SignatureCalculationRequiresMessage()
        {
            var signature = GetTestSignature();

            Action task = () => signature.Calculate(null, TestNonce, TestClock.TestValue);
            task.Should().ThrowExactly<ArgumentNullException>();
        }

        [Fact]
        public void SignatureCalculationRequiresNonce()
        {
            var signature = GetTestSignature();

            Action task = () => signature.Calculate(GetTestMessage(), null, TestClock.TestValue);
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public void SignatureCalculationRequiresTimestamp()
        {
            var signature = GetTestSignature();

            Action task = () => signature.Calculate(GetTestMessage(), TestNonce, default);
            task.Should().ThrowExactly<ArgumentException>();
        }

        [Fact]
        public void SignatureCalculationRewindsBodyStream()
        {
            var signature = GetTestSignature();
            var message = GetTestMessage(new string(' ', 100));

            try
            {
                signature.Calculate(message, TestNonce, TestClock.TestValue);
            }
            catch (NotImplementedException) { }

            message.Body.Position.Should().Be(0);
        }

        [Fact]
        public void SignatureCalculationResetsBodyStreamToOriginalPosition()
        {
            const int Offset = 50;
            var signature = GetTestSignature();
            var message = GetTestMessage(new string(' ', 100));
            message.Body.Seek(Offset, SeekOrigin.Begin);

            try
            {
                signature.Calculate(message, TestNonce, TestClock.TestValue);
            }
            catch (NotImplementedException) { }

            message.Body.Position.Should().Be(Offset);
        }

        [Fact]
        public void CalculatedSignatureIsConsistent()
        {
            var signature = GetTestSignature();
            var message = GetTestMessage();
            var expected = new byte[] {
                105, 165, 255, 192, 146, 98, 37, 143,
                37, 194, 192, 246, 115, 7, 11, 253,
                19, 145, 211, 31, 241, 77, 58, 25,
                6, 41, 19, 0, 223, 136, 62, 80 };

            var hash = signature.Calculate(message, TestNonce, TestClock.TestValue);
            hash.Should().Equal(expected);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentHttpMethods()
        {
            var getSignature = GetTestSignature();
            var getMessage = GetTestMessage();
            var postSignature = GetTestSignature();
            var postMessage = GetTestMessage(); postMessage.Method = "POST";

            var hash1 = getSignature.Calculate(getMessage, TestNonce, TestClock.TestValue);
            var hash2 = postSignature.Calculate(postMessage, TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsTheSameWhenHttpMethodCasingIsDifferent()
        {
            var signature1 = GetTestSignature();
            var message1 = GetTestMessage(); message1.Method = "GET";
            var signature2 = GetTestSignature();
            var message2 = GetTestMessage(); message2.Method = "get";

            var hash1 = signature1.Calculate(message1, TestNonce, TestClock.TestValue);
            var hash2 = signature2.Calculate(message2, TestNonce, TestClock.TestValue);
            hash1.Should().Equal(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentUrls()
        {
            var signature1 = GetTestSignature();
            var message1 = GetTestMessage(); message1.Uri = "http://localhost:5000/?test=1";
            var signature2 = GetTestSignature();
            var message2 = GetTestMessage(); message2.Uri = "http://localhost:5000/?test=2";

            var hash1 = signature1.Calculate(message1, TestNonce, TestClock.TestValue);
            var hash2 = signature2.Calculate(message2, TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentNonces()
        {
            var signature1 = GetTestSignature();
            var signature2 = GetTestSignature();
            var message = GetTestMessage();

            var hash1 = signature1.Calculate(message, TestNonce, TestClock.TestValue);
            var hash2 = signature2.Calculate(message, TestNonce2, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentTimestamps()
        {
            var signature1 = GetTestSignature();
            var signature2 = GetTestSignature();
            var message = GetTestMessage();

            var hash1 = signature1.Calculate(message, TestNonce, TestClock.TestValue);
            var hash2 = signature2.Calculate(message, TestNonce, TestClock.TestValue.AddMinutes(5));
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsTheSameWhenTimestampsDifferOnlyInMilliseconds()
        {
            var signature1 = GetTestSignature();
            var signature2 = GetTestSignature();
            var message = GetTestMessage();

            var hash1 = signature1.Calculate(message, TestNonce, TestClock.TestValue);
            var hash2 = signature2.Calculate(message, TestNonce, TestClock.TestValue.AddMilliseconds(100));
            hash1.Should().Equal(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentBodies()
        {
            var signature1 = GetTestSignature();
            var message1 = GetTestMessage("{ \"test\": 1}");
            var signature2 = GetTestSignature();
            var message2 = GetTestMessage("{ \"test\": 2}");

            var hash1 = signature1.Calculate(message1, TestNonce, TestClock.TestValue);
            var hash2 = signature2.Calculate(message2, TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void CalculatedSignatureIsDifferentForDifferentKeys()
        {
            var signature1 = GetTestSignature();
            var message1 = GetTestMessage();
            var signature2 = GetTestSignature(); signature2.Key = TestKeyLookup.TestKey2;
            var message2 = GetTestMessage();

            var hash1 = signature1.Calculate(message1, TestNonce, TestClock.TestValue);
            var hash2 = signature2.Calculate(message2, TestNonce, TestClock.TestValue);
            hash1.Should().NotEqual(hash2);
        }

        [Fact]
        public void SignatureValidatesCorrectlyWithTheSameParameters()
        {
            var signature = GetTestSignature();
            var message = GetTestMessage();
            signature.Hash = signature.Calculate(message, TestNonce, TestClock.TestValue);

            var result = signature.Validate(message, TestNonce, TestClock.TestValue);
            result.Should().BeTrue();
        }

        [Fact]
        public void SignatureValidatesCorrectlyWithTimestampWithinSameSecond()
        {
            var signature = GetTestSignature();
            var message = GetTestMessage();
            signature.Hash = signature.Calculate(message, TestNonce, TestClock.TestValue);

            var result = signature.Validate(message, TestNonce, TestClock.TestValue.AddMilliseconds(100));
            result.Should().BeTrue();
        }

        [Fact]
        public void SignatureFailsToValidateWithDifferentNonce()
        {
            var signature = GetTestSignature();
            var message = GetTestMessage();
            signature.Hash = signature.Calculate(message, TestNonce, TestClock.TestValue);

            var result = signature.Validate(message, TestNonce2, TestClock.TestValue);
            result.Should().BeFalse();
        }

        [Fact]
        public void SignatureFailsToValidateWithDifferentTimestamp()
        {
            var signature = GetTestSignature();
            var message = GetTestMessage();
            signature.Hash = signature.Calculate(message, TestNonce, TestClock.TestValue);

            var result = signature.Validate(message, TestNonce, TestClock.TestValue.AddMinutes(5));
            result.Should().BeFalse();
        }

        [Fact]
        public void SignatureFailsToValidateWithDifferentMessage()
        {
            var signature = GetTestSignature();
            var message = GetTestMessage();
            signature.Hash = signature.Calculate(message, TestNonce, TestClock.TestValue);

            var message2 = GetTestMessage("2");
            var result = signature.Validate(message2, TestNonce, TestClock.TestValue);
            result.Should().BeFalse();
        }

        private HttpSignature GetTestSignature()
        {
            return new HttpSignature
            {
                Key = TestKeyLookup.TestKey,
                Algorithm = "HMACSHA256",
                ContentAlgorithm = "SHA256"
            };
        }

        private HttpMessage GetTestMessage(string body = "")
        {
            return new HttpMessage
            {
                Method = "GET",
                Uri = "http://localhost:5000/api/test/1?value=2011-12-20T12:13:21Z",
                Body = new StringStream(body)
            };
        }
    }
}