using System;

namespace Decos.Http.Signatures.Validation
{
    /// <summary>
    /// Represents the error that occurs when a key identifier does not have an associated key.
    /// </summary>
    public class KeyNotFoundException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="KeyNotFoundException"/> class with a default
        /// error message.
        /// </summary>
        public KeyNotFoundException()
            : base(Strings.KeyNotFound)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyNotFoundException"/> class with a
        /// specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public KeyNotFoundException(string message)
            : base(message)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyNotFoundException"/> class with a
        /// specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        /// <param name="keyId">The key identifier that could not be found.</param>
        public KeyNotFoundException(string message, string keyId)
            : this(message)
        {
            KeyId = keyId;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyNotFoundException"/> class with a
        /// specified error message and a reference to the inner exception that is the cause of this
        /// exception.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception.
        /// </param>
        /// <param name="innerException">
        /// The exception that is the cause of the current exception, or a null reference (Nothing in
        /// Visual Basic) if no inner exception is specified.
        /// </param>
        public KeyNotFoundException(string message, Exception innerException)
            : base(message, innerException)
        {
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyNotFoundException"/> class with a
        /// specified error message and a reference to the inner exception that is the cause of this
        /// exception.
        /// </summary>
        /// <param name="message">
        /// The error message that explains the reason for the exception.
        /// </param>
        /// <param name="keyId">The key identifier that could not be found.</param>
        /// <param name="innerException">
        /// The exception that is the cause of the current exception, or a null reference (Nothing in
        /// Visual Basic) if no inner exception is specified.
        /// </param>
        public KeyNotFoundException(string message, string keyId, Exception innerException)
            : this(message, innerException)
        {
            KeyId = keyId;
        }

        /// <summary>
        /// Gets the identifier of the key that could not be found.
        /// </summary>
        public string KeyId { get; }

        /// <summary>
        /// Creates a new <see cref="KeyNotFoundException"/> for the specified key ID.
        /// </summary>
        /// <param name="keyId">The identifier of the key that could not be found.</param>
        /// <returns>A new <see cref="KeyNotFoundException"/>.</returns>
        public static KeyNotFoundException WithId(string keyId)
        {
            return new KeyNotFoundException(string.Format(Strings.KeyNotFound_WithId, keyId),
                keyId);
        }
    }
}