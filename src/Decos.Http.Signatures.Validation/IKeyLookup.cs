using System;
using System.Threading;
using System.Threading.Tasks;

namespace Decos.Http.Signatures.Validation
{
    /// <summary>
    /// Defines a mechanism for looking up cryptographic keys.
    /// </summary>
    public interface IKeyLookup
    {
        /// <summary>
        /// Gets the cryptographic key associated with the specified ID.
        /// </summary>
        /// <param name="keyId">The ID of the key to find.</param>
        /// <returns>
        /// A byte array containing the cryptographic key associated with <paramref name="keyId"/>,
        /// if the key could be found. Otherwise, returns <c>null</c>.
        /// </returns>
        Task<byte[]> GetKeyOrDefaultAsync(string keyId);
    }
}