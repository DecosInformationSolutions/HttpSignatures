using System;

namespace Decos.Http.Signatures.Validation
{
    /// <summary>
    /// Specifies the result of signature validation.
    /// </summary>
    public enum SignatureValidationResult
    {
        /// <summary>
        /// The signature is valid.
        /// </summary>
        OK = 0,

        /// <summary>
        /// The signature does not match.
        /// </summary>
        Invalid = 1,

        /// <summary>
        /// The signature has expired or is not yet valid.
        /// </summary>
        Expired = 2,

        /// <summary>
        /// The signature nonce has been seen before.
        /// </summary>
        Duplicate = 3,
    }
}