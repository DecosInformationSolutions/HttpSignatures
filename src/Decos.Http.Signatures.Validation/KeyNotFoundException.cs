using System;

namespace Decos.Http.Signatures.Validation
{
    public class KeyNotFoundException : Exception
    {
        public KeyNotFoundException()
            : base(Strings.KeyNotFound)
        {
        }

        public KeyNotFoundException(string message)
            : base(message)
        {
        }

        public KeyNotFoundException(string message, string keyId)
            : this(message)
        {
            KeyId = keyId;
        }

        public KeyNotFoundException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        public KeyNotFoundException(string message, string keyId, Exception innerException)
            : this(message, innerException)
        {
            KeyId = keyId;
        }

        public string KeyId { get; }

        public static KeyNotFoundException WithId(string keyId)
        {
            return new KeyNotFoundException(string.Format(Strings.KeyNotFound_WithId, keyId),
                keyId);
        }
    }
}