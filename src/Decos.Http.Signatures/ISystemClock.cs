using System;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Defines a mechanism for retrieving the current system time.
    /// </summary>
    public interface ISystemClock
    {
        /// <summary>
        /// Gets the current system time in UTC.
        /// </summary>
        DateTimeOffset UtcNow { get; }
    }
}