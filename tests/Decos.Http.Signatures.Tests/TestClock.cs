using System;
using System.Collections.Generic;
using System.Text;

namespace Decos.Http.Signatures.Tests
{
    public class TestClock : ISystemClock
    {
        public static readonly DateTimeOffset TestValue
            = new DateTimeOffset(2011, 12, 20, 12, 13, 21, 0, TimeSpan.Zero);

        public DateTimeOffset UtcNow => TestValue;
    }
}
