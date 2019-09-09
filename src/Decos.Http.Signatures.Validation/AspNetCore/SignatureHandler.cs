using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;

using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Decos.Http.Signatures.Validation.AspNetCore
{
    /// <summary>
    /// Represents an authentication handler that authenticates requests with a valid signature.
    /// </summary>
    public class SignatureHandler : AuthenticationHandler<SignatureOptions>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="SignatureHandler"/> class.
        /// </summary>
        /// <param name="validator">Used to validate signatures.</param>
        /// <param name="options">The signature options.</param>
        /// <param name="logger">A factory used to create logger instances.</param>
        /// <param name="encoder">A URL encoder.</param>
        /// <param name="clock">Used to get the current time.</param>
        public SignatureHandler(HttpSignatureValidator validator,
            IOptionsMonitor<SignatureOptions> options,
            ILoggerFactory logger,
            System.Text.Encodings.Web.UrlEncoder encoder,
            Microsoft.AspNetCore.Authentication.ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
            Validator = validator;
        }

        /// <summary>
        /// Gets the <see cref="HttpSignatureValidator"/> used to validate signatures.
        /// </summary>
        protected HttpSignatureValidator Validator { get; }

        /// <summary>
        /// Determines whether the current request is authenticated.
        /// </summary>
        /// <returns>
        /// A task that returns a value indicating whether the authentication succeeded.
        /// </returns>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.TryGetValue("Authorization", out var value))
                return AuthenticateResult.NoResult();

            var authValue = value.LastOrDefault(x => x.StartsWith(Options.AuthenticationScheme));
            if (authValue == null)
                return AuthenticateResult.NoResult();

            authValue = authValue.Substring(Options.AuthenticationScheme.Length).TrimStart();
            var signature = HttpSignature.Parse(authValue);
            var result = await Validator.ValidateAsync(Request, signature).ConfigureAwait(false);
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

        /// <summary>
        /// Adds authentication details to the challenge response.
        /// </summary>
        /// <param name="properties">Contains values about the authentication session.</param>
        /// <returns>A task that represents the asynchronous operation.</returns>
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            Response.Headers["WWW-Authenticate"] = "Signature";
            return base.HandleChallengeAsync(properties);
        }

        /// <summary>
        /// Creates a new authentication ticket for the specified signature.
        /// </summary>
        /// <param name="signature">The signature to authenticate.</param>
        /// <returns>A new <see cref="AuthenticationTicket"/>.</returns>
        protected virtual AuthenticationTicket TicketFor(HttpSignature signature)
        {
            var identity = new ClaimsIdentity(Options.AuthenticationScheme);
            identity.AddClaim(new Claim(identity.NameClaimType, signature.KeyId));

            var principal = new ClaimsPrincipal(identity);
            return new AuthenticationTicket(principal, Options.AuthenticationScheme);
        }
    }
}