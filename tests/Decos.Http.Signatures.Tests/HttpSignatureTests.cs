using System;
using System.Collections;
using System.IO;
using System.Threading.Tasks;

using FluentAssertions;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class HttpSignatureTests
    {
        private const string TestNonce = "a1d76f81-de54-498c-8ccf-7ed9e069596a";

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