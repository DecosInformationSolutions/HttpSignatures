using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text.RegularExpressions;
using System.Xml;

namespace Decos.Http.Signatures
{
    public class SignatureParams
    {
        public string KeyId { get; set; }

        public string Nonce { get; set; }

        public DateTimeOffset Timestamp { get; set; }

        public byte[] Signature { get; set; }

        public static SignatureParams Parse(string serializedString)
        {
            var items = Deserialize(serializedString);

            if (!items.TryGetValue("keyId", out var keyId) || keyId is null)
                throw new FormatException("The 'keyId' value is missing.");

            if (!items.TryGetValue("nonce", out var nonce) || nonce is null)
                throw new FormatException("The 'nonce' value is missing.");

            if (!items.TryGetValue("created", out var created) || created is null)
                throw new FormatException("The 'created' value is missing.");
            var timestamp = ParseCreated(created);

            if (!items.TryGetValue("signature", out var signature) || signature is null)
                throw new FormatException("The 'signature' value is missing.");
            var signatureHash = Convert.FromBase64String(signature);

            return new SignatureParams
            {
                KeyId = keyId,
                Nonce = nonce,
                Timestamp = timestamp,
                Signature = signatureHash
            };
        }

        private static DateTimeOffset ParseCreated(string created)
        {
            if (DateTimeOffset.TryParse(created, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dateTime))
                return dateTime;

            if (long.TryParse(created, out var seconds))
                return DateTimeOffset.FromUnixTimeSeconds(seconds);

            throw new FormatException($"The 'created' value is not a recognized date/time value. Value: \"{created}\"");
        }

        public override string ToString()
        {
            throw new NotImplementedException();
        }

        private static Dictionary<string, string> Deserialize(string serializedString)
        {
            var regex = new Regex("(([^,=]+)(=(\"([^\"]*)\"|([^,\"]*)))?)+");

            var dictionary = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (Match match in regex.Matches(serializedString))
            {
                var key = match.Groups[2].GetValueOrDefault();
                var value = match.Groups[5].GetValueOrDefault()
                    ?? match.Groups[6].GetValueOrDefault();
                dictionary.Add(key, value);
            }
            return dictionary;
        }
    }
}