using System;
using System.Globalization;
using FluentAssertions;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class SignatureParamsTests
    {
        [Fact]
        public void KeyIdCanBeParsed()
        {
            const string keyId = "test";
            const string serializedString = "keyId=" + keyId + ",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = SignatureParams.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void KeyIdCanBeParsedCaseInsensitive()
        {
            const string keyId = "test";
            const string serializedString = "KEYID=" + keyId + ",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = SignatureParams.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void QuotedKeyIdCanBeParsed()
        {
            const string keyId = "te,st";
            const string serializedString = "keyId=\"" + keyId + "\",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = SignatureParams.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void NonceCanBeParsed()
        {
            const string nonce = "99e3006e-b846-4fe6-9572-6b5e2031773f";
            const string serializedString = "keyId=\"test\",nonce=\"" + nonce + "\",created=1,signature=\"OSQPsZ+PegY=\"";

            var param = SignatureParams.Parse(serializedString);

            param.Nonce.Should().Be(nonce);
        }

        [Fact]
        public void TimestampCanBeParsedFromIso8601String()
        {
            var timestamp = TestClock.TestValue;
            var serializedString = "keyId=test,nonce=test,created=\"" + timestamp.ToString("s", CultureInfo.InvariantCulture) + "\",signature=\"OSQPsZ+PegY=\"";

            var param = SignatureParams.Parse(serializedString);

            param.Timestamp.Should().Be(timestamp);
        }

        [Fact]
        public void SignatureCanBeParsed()
        {
            var hash = new byte[8] { 57, 36, 15, 177, 159, 143, 122, 6 };
            const string serializedString = "keyId=\"test\",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = SignatureParams.Parse(serializedString);

            param.Signature.Should().Equal(hash);
        }
    }
}