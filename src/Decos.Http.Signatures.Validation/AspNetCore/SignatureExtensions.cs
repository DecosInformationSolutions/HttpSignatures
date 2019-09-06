using System;

using Microsoft.AspNetCore.Authentication;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    /// <summary>
    /// Provides a set of static methods for configuring Signature authentication.
    /// </summary>
    public static class SignatureExtensions
    {
        /// <summary>
        /// Adds HTTP signature authentication to the application.
        /// </summary>
        /// <param name="builder">Used to configure authentication.</param>
        /// <returns>A builder used to configure authentication.</returns>
        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder)
        {
            return builder.AddSignature(SignatureDefaults.AuthenticationScheme, _ => { });
        }

        /// <summary>
        /// Adds HTTP signature authentication to the application.
        /// </summary>
        /// <param name="builder">Used to configure authentication.</param>
        /// <param name="configureOptions">Used to configure the scheme options.</param>
        /// <returns>A builder used to configure authentication.</returns>
        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder,
            Action<SignatureOptions> configureOptions)
        {
            return builder.AddSignature(SignatureDefaults.AuthenticationScheme,
                configureOptions);
        }

        /// <summary>
        /// Adds HTTP signature authentication to the application.
        /// </summary>
        /// <param name="builder">Used to configure authentication.</param>
        /// <param name="authenticationScheme">The name of this scheme.</param>
        /// <param name="configureOptions">Used to configure the scheme options.</param>
        /// <returns>A builder used to configure authentication.</returns>
        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder,
            string authenticationScheme, Action<SignatureOptions> configureOptions)
        {
            return builder.AddSignature(authenticationScheme,
                displayName: null,
                configureOptions: configureOptions);
        }

        /// <summary>
        /// Adds HTTP signature authentication to the application.
        /// </summary>
        /// <param name="builder">Used to configure authentication.</param>
        /// <param name="authenticationScheme">The name of this scheme.</param>
        /// <param name="displayName">The display name of this scheme.</param>
        /// <param name="configureOptions">Used to configure the scheme options.</param>
        /// <returns>A builder used to configure authentication.</returns>
        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder,
            string authenticationScheme, string displayName, Action<SignatureOptions> configureOptions)
        {
            return builder.AddScheme<SignatureOptions, SignatureHandler>(authenticationScheme,
                displayName,
                configureOptions);
        }
    }
}