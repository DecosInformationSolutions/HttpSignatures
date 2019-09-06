using System;
using System.Globalization;

using FluentAssertions;

using Xunit;

namespace Decos.Http.Signatures.Tests
{
    public class HttpSignatureTests
    {
        [Fact]
        public void KeyIdCanBeParsed()
        {
            const string keyId = "test";
            const string serializedString = "keyId=" + keyId + ",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = HttpSignature.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void KeyIdCanBeParsedCaseInsensitive()
        {
            const string keyId = "test";
            const string serializedString = "KEYID=" + keyId + ",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = HttpSignature.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void QuotedKeyIdCanBeParsed()
        {
            const string keyId = "te,st";
            const string serializedString = "keyId=\"" + keyId + "\",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = HttpSignature.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void NonceCanBeParsed()
        {
            const string nonce = "99e3006e-b846-4fe6-9572-6b5e2031773f";
            const string serializedString = "keyId=\"test\",nonce=\"" + nonce + "\",created=1,signature=\"OSQPsZ+PegY=\"";

            var param = HttpSignature.Parse(serializedString);

            param.Nonce.Should().Be(nonce);
        }

        [Fact]
        public void TimestampCanBeParsedFromIso8601String()
        {
            var timestamp = TestClock.TestValue;
            var serializedString = "keyId=test,nonce=test,created=\"" + timestamp.ToString("s", CultureInfo.InvariantCulture) + "\",signature=\"OSQPsZ+PegY=\"";

            var param = HttpSignature.Parse(serializedString);

            param.Timestamp.Should().Be(timestamp);
        }

        [Fact]
        public void TimestampCanBeParsedFromUnixTimestamp()
        {
            var timestamp = TestClock.TestValue;
            var serializedString = "keyId=test,nonce=test,created=\"" + timestamp.ToUnixTimeSeconds().ToString() + "\",signature=\"OSQPsZ+PegY=\"";

            var param = HttpSignature.Parse(serializedString);

            param.Timestamp.Should().Be(timestamp);
        }

        [Fact]
        public void ExceptionIsThrownForInvalidTimestamp()
        {
            var serializedString = "keyId=test,nonce=test,created=\"undefined\",signature=\"OSQPsZ+PegY=\"";

            Action parse = () => HttpSignature.Parse(serializedString);

            parse.Should().Throw<FormatException>();
        }

        [Fact]
        public void StringCannotBeParsedWithoutKeyId()
        {
            var serializedString = "nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            Action parse = () => HttpSignature.Parse(serializedString);

            parse.Should().Throw<FormatException>();
        }

        [Fact]
        public void StringCannotBeParsedWithoutNonce()
        {
            var serializedString = "keyId=test,created=1,signature=\"OSQPsZ+PegY=\"";

            Action parse = () => HttpSignature.Parse(serializedString);

            parse.Should().Throw<FormatException>();
        }

        [Fact]
        public void StringCannotBeParsedWithoutTimestamp()
        {
            var serializedString = "keyId=test,nonce=test,signature=\"OSQPsZ+PegY=\"";

            Action parse = () => HttpSignature.Parse(serializedString);

            parse.Should().Throw<FormatException>();
        }

        [Fact]
        public void StringCannotBeParsedWithoutSignature()
        {
            var serializedString = "keyId=test,nonce=test,created=1";

            Action parse = () => HttpSignature.Parse(serializedString);

            parse.Should().Throw<FormatException>();
        }

        [Fact]
        public void SignatureCanBeParsed()
        {
            var hash = new byte[8] { 57, 36, 15, 177, 159, 143, 122, 6 };
            const string serializedString = "keyId=\"test\",nonce=test,created=1,signature=\"OSQPsZ+PegY=\"";

            var param = HttpSignature.Parse(serializedString);

            param.Hash.Should().Equal(hash);
        }

        [Fact]
        public void SignatureStringContainsKeyId()
        {
            const string keyId = "748f064f-5b4d-44cb-b645-a673924743e3";
            var param = GetRandomParams();
            param.KeyId = keyId;

            param.ToString().Should().Contain("keyId=\"" + keyId + "\"");
        }

        [Fact]
        public void SignatureStringContainsNonce()
        {
            const string nonce = "b0956505-e268-4db8-927e-1380a0c18be8";
            var param = GetRandomParams();
            param.Nonce = nonce;

            param.ToString().Should().Contain("nonce=\"" + nonce + "\"");
        }

        [Fact]
        public void SignatureStringContainsUnixTimestamp()
        {
            var created = new DateTimeOffset(2011, 12, 20, 12, 13, 21, 0, TimeSpan.Zero);
            var param = GetRandomParams();
            param.Timestamp = created;

            param.ToString().Should().Contain("created=\"" + created.ToUnixTimeSeconds() + "\"");
        }

        [Fact]
        public void SignatureStringContainsBase64Signature()
        {
            var hash = new byte[] {
                29, 220, 94, 172, 49, 95, 46, 159,
                185, 16, 134, 229, 47, 253, 143, 215,
                41, 113, 63, 141, 224, 4, 117, 67,
                212, 79, 228, 14, 84, 228, 190, 198 };
            var param = GetRandomParams();
            param.Hash = hash;

            param.ToString().Should().Contain("signature=\"" + Convert.ToBase64String(hash) + "\"");
        }

        [Fact]
        public void SignatureParamsCanBeSerializedAndDeserialized()
        {
            var expected = GetRandomParams();

            var actual = HttpSignature.Parse(expected.ToString());

            actual.KeyId.Should().Be(expected.KeyId);
            actual.Nonce.Should().Be(expected.Nonce);
            actual.Timestamp.Should().BeCloseTo(expected.Timestamp, TimeSpan.FromSeconds(1));
            actual.Hash.Should().Equal(expected.Hash);
        }

        private HttpSignature GetRandomParams()
        {
            return new HttpSignature
            {
                KeyId = Guid.NewGuid().ToString(),
                Nonce = Guid.NewGuid().ToString(),
                Timestamp = DateTimeOffset.UtcNow,
                Hash = Guid.NewGuid().ToByteArray()
            };
        }
    }
}