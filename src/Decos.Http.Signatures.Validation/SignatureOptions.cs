using System;
using System.Security.Cryptography;

namespace Decos.Http.Signatures.Validation
{
    /// <summary>
    /// Represents the options that control signature calculation and validation.
    /// </summary>
    public class SignatureOptions
    {
        /// <summary>
        /// Gets or sets the name of the keyed hash algorithm to use for calculating a signature when
        /// no other algorithm is specified.
        /// </summary>
        public string DefaultAlgorithm { get; set; } = nameof(HMACSHA256);

        /// <summary>
        /// Gets or sets the name of the general purpose hash algorithm to use for calculating a hash
        /// of the message content when no other algorithm is specified;
        /// </summary>
        public string DefaultContentAlgorithm { get; set; } = nameof(SHA256);

        /// <summary>
        /// Gets or sets the maximum amount of time allowed between the creation and validation of a
        /// signature.
        /// </summary>
        public TimeSpan ClockSkewMargin { get; set; } = TimeSpan.FromMinutes(5);

        /// <summary>
        /// Gets or sets the amount of time a nonce should remain unique.
        /// </summary>
        public TimeSpan NonceExpiration { get; set; } = TimeSpan.FromMinutes(15);
    }
}