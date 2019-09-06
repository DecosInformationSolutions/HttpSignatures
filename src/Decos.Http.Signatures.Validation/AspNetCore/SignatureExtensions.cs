using System;

using Microsoft.AspNetCore.Authentication;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    public static class SignatureExtensions
    {
        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder)
        {
            return builder.AddSignature(SignatureDefaults.AuthenticationScheme, _ => { });
        }

        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder,
            Action<SignatureOptions> configureOptions)
        {
            return builder.AddSignature(SignatureDefaults.AuthenticationScheme,
                configureOptions);
        }

        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder,
            string authenticationScheme, Action<SignatureOptions> configureOptions)
        {
            return builder.AddSignature(authenticationScheme,
                displayName: null,
                configureOptions: configureOptions);
        }

        public static AuthenticationBuilder AddSignature(this AuthenticationBuilder builder,
            string authenticationScheme, string displayName, Action<SignatureOptions> configureOptions)
        {
            return builder.AddScheme<SignatureOptions, SignatureHandler>(authenticationScheme, 
                displayName, 
                configureOptions);
        }
    }
}