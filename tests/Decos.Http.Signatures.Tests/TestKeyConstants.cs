using System;
using System.Collections.Generic;
using System.Text;

namespace Decos.Http.Signatures.Tests
{
    public static class TestKeyConstants
    {
        public const string ValidKeyId = "90694e5216a5f4db";
        public const string InvalidKeyId = "e2a24c1d71579ae0";

        public static readonly byte[] TestKey = new byte[] {
            226, 115, 163, 94, 84, 108, 198, 198,
            83, 27, 221, 186, 237, 50, 62, 146,
            235, 196, 137, 217, 240, 82, 60, 124,
            183, 152, 235, 97, 174, 219, 44, 75 };

        public static readonly byte[] TestKey2 = new byte[] {
            207, 11, 82, 250, 46, 152, 92, 84,
            77, 157, 49, 218, 72, 124, 21, 158,
            13, 46, 189, 190, 2, 99, 181, 235,
            139, 110, 13, 128, 230, 244, 222, 134 };
    }
}
