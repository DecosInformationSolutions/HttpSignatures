using System;

using Decos.Http.Signatures.Validation;
using Decos.Http.Signatures.Validation.AspNetCore;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Microsoft.Extensions.DependencyInjection
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
            Action<SignatureHandlerOptions> configureOptions)
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
            string authenticationScheme, Action<SignatureHandlerOptions> configureOptions)
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
            string authenticationScheme, string displayName, Action<SignatureHandlerOptions> configureOptions)
        {
            builder.Services.AddSignatureValidation();
            return builder.AddScheme<SignatureHandlerOptions, SignatureHandler>(authenticationScheme,
                displayName,
                configureOptions);
        }

        /// <summary>
        /// Adds the services required for HTTP signature validation.
        /// </summary>
        /// <param name="services">The service collection to configure.</param>
        /// <returns>The configured service collection.</returns>
        public static IServiceCollection AddSignatureValidation(this IServiceCollection services)
        {
            services.TryAddSingleton<Decos.Http.Signatures.ISystemClock, Decos.Http.Signatures.SystemClock>();
            services.TryAddTransient<HttpSignatureValidator>();
            return services;
        }
    }
}