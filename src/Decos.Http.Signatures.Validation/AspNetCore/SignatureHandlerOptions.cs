using System;
using Microsoft.AspNetCore.Authentication;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    /// <summary>
    /// Provides options for configuring a <see cref="SignatureHandler"/>.
    /// </summary>
    public class SignatureHandlerOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Gets or sets the scheme used in the Authorization header value.
        /// </summary>
        public string AuthenticationScheme { get; set; } = SignatureDefaults.AuthenticationScheme;
    }
}