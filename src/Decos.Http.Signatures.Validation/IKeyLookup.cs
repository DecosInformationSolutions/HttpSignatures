using System;
using System.Threading.Tasks;

namespace Decos.Http.Signatures.Validation
{
    /// <summary>
    /// Defines a mechanism for looking up cryptographic keys.
    /// </summary>
    public interface IKeyLookup
    {
        /// <summary>
        /// Gets the cryptographic key associated with the specified ID and returns a value
        /// indicating whether the key was found.
        /// </summary>
        /// <param name="keyId">The ID of the key to find.</param>
        /// <param name="key">
        /// When this method returns, contains the cryptographic key associated with the specified
        /// ID, if it is found.
        /// </param>
        /// <returns><c>true</c> if the key could be found; otherwise, <c>false</c>.</returns>
        Task<bool> TryGetKeyAsync(string keyId, out byte[] key);
    }
}