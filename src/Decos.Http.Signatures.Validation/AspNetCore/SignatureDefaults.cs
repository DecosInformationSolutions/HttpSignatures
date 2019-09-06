using System;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    /// <summary>
    /// Provides the default values used in signature authentication.
    /// </summary>
    public static class SignatureDefaults
    {
        /// <summary>
        /// The default scheme for signature authentication.
        /// </summary>
        public const string AuthenticationScheme = "Signature";
    }
}