using System;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Gets the current system time in UTC.
    /// </summary>
    public class SystemClock : ISystemClock
    {
        /// <summary>
        /// Gets the current system time in UTC.
        /// </summary>
        public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
    }
}