using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    public class SignatureHandler : AuthenticationHandler<SignatureOptions>
    {
        public SignatureHandler(HttpSignatureValidator validator,
            IOptionsMonitor<SignatureOptions> options,
            ILoggerFactory logger,
            System.Text.Encodings.Web.UrlEncoder encoder,
            Microsoft.AspNetCore.Authentication.ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            Validator = validator;
        }

        protected HttpSignatureValidator Validator { get; }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out var value))
                return AuthenticateResult.NoResult();

            var authValue = value.LastOrDefault(x => x.StartsWith(Options.AuthenticationScheme));
            if (authValue == null)
                return AuthenticateResult.NoResult();

            authValue = authValue.Substring(Options.AuthenticationScheme.Length).TrimStart();
            var signature = HttpSignature.Parse(authValue);
            var result = await Validator.ValidateAsync(Request, signature);
            switch (result)
            {
                case SignatureValidationResult.OK:
                    return AuthenticateResult.Success(TicketFor(signature));

                case SignatureValidationResult.Invalid:
                    Logger.LogInformation("Invalid signature with key ID {KeyId}",
                        signature.KeyId);
                    break;

                case SignatureValidationResult.Expired:
                    Logger.LogInformation("Expired signature with key ID {KeyId}, created {Timestamp}",
                        signature.KeyId, signature.Timestamp);
                    break;

                case SignatureValidationResult.Duplicate:
                    Logger.LogInformation("Duplicate signature with key ID {KeyId}, nonce {Nonce}",
                        signature.KeyId, signature.Nonce);
                    break;

                default:
                    return AuthenticateResult.Fail("Invalid validation result: " + result);
            }

            return AuthenticateResult.NoResult();
        }

        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers["WWW-Authenticate"] = "Signature";
            return base.HandleChallengeAsync(properties);
        }

        protected virtual AuthenticationTicket TicketFor(HttpSignature signature)
        {
            var identity = new ClaimsIdentity(Options.AuthenticationScheme);
            identity.AddClaim(new Claim(identity.NameClaimType, signature.KeyId));
            var principal = new ClaimsPrincipal(identity);
            return new AuthenticationTicket(principal, Options.AuthenticationScheme);
        }
    }
}
