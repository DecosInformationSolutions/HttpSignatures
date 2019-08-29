using System;
using System.Threading.Tasks;

namespace Decos.Http.Signatures.Tests
{
    public class TestKeyLookup : IKeyLookup
    {
        public static readonly byte[] TestKey = new byte[] {
            226, 115, 163, 94, 84, 108, 198, 198,
            83, 27, 221, 186, 237, 50, 62, 146,
            235, 196, 137, 217, 240, 82, 60, 124,
            183, 152, 235, 97, 174, 219, 44, 75 };

        public Task<bool> TryGetKeyAsync(string keyId, out byte[] key)
        {
            key = TestKey;
            return Task.FromResult(true);
        }
    }
}