using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace Decos.Http.Signatures
{
    public class SignatureParams
    {
        public string KeyId { get; set; }

        public string Algorithm { get; set; }

        public string ContentAlgorithm { get; set; }

        public byte[] Signature { get; set; }

        public static SignatureParams Parse(string serializedString)
        {
            var items = Deserialize(serializedString);

            if (!items.TryGetValue("keyId", out var keyId))
                throw new FormatException("A keyId was not specified.");

            items.TryGetValue("algorithm", out var algorithm);
            items.TryGetValue("contentAlgorithm", out var contentAlgorithm);

            byte[] signatureHash = null;
            if (items.TryGetValue("signature", out var signature))
                signatureHash = Convert.FromBase64String(signature);

            return new SignatureParams
            {
                KeyId = keyId,
                Algorithm = algorithm,
                ContentAlgorithm = contentAlgorithm,
                Signature = signatureHash
            };
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