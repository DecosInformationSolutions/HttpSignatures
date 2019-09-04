using System;

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
            const string serializedString = "keyId=" + keyId;

            var param = SignatureParams.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void KeyIdCanBeParsedCaseInsensitive()
        {
            const string keyId = "test";
            const string serializedString = "KEYID=" + keyId;

            var param = SignatureParams.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void QuotedKeyIdCanBeParsed()
        {
            const string keyId = "te,st";
            const string serializedString = "keyId=\"" + keyId + "\"";

            var param = SignatureParams.Parse(serializedString);

            param.KeyId.Should().Be(keyId);
        }

        [Fact]
        public void ParamsCannotBeParsedWithoutKeyId()
        {
            const string serializedString = "algorithm=\"HMACSHA256\",signature=\"OSQPsZ+PegY=\"";

            Action parse = () => SignatureParams.Parse(serializedString);

            parse.Should().Throw<FormatException>();
        }

        [Fact]
        public void AlgorithmCanBeParsed()
        {
            const string algorithm = "HMACSHA256";
            const string serializedString = "keyId=\"test\",algorithm=\"" + algorithm + "\"";

            var param = SignatureParams.Parse(serializedString);

            param.Algorithm.Should().Be(algorithm);
        }

        [Fact]
        public void ContentAlgorithmCanBeParsed()
        {
            const string algorithm = "SHA256";
            const string serializedString = "keyId=\"test\",contentAlgorithm=\"" + algorithm + "\"";

            var param = SignatureParams.Parse(serializedString);

            param.ContentAlgorithm.Should().Be(algorithm);
        }

        [Fact]
        public void SignatureCanBeParsed()
        {
            var hash = new byte[8] { 57, 36, 15, 177, 159, 143, 122, 6 };
            const string serializedString = "keyId=\"test\",signature=\"OSQPsZ+PegY=\"";

            var param = SignatureParams.Parse(serializedString);

            param.Signature.Should().Equal(hash);
        }
    }
}