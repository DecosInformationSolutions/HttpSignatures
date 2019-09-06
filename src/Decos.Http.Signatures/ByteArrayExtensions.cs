using System;

namespace Decos.Http.Signatures
{
    /// <summary>
    /// Provides a set of static methods that add functionality to byte arrays.
    /// </summary>
    public static class ByteArrayExtensions
    {
        /// <summary>
        /// Determines whether two hashes are equal by comparing all elements. This method always
        /// compares all elements and does not return early, making it suitable for comparing
        /// cryptographic hashes.
        /// </summary>
        /// <param name="value">The first byte array.</param>
        /// <param name="other">The byte array to compare with.</param>
        /// <returns>
        /// <c>true</c> if <paramref name="value"/> and <paramref name="other"/> are equal;
        /// otherwise, <c>false</c>.
        /// </returns>
        public static bool HashEquals(this byte[] value, byte[] other)
        {
            var diff = (uint)value.Length ^ (uint)other.Length;
            for (int i = 0; i < value.Length && i < other.Length; i++)
                diff |= (uint)(value[i] ^ other[i]);
            return diff == 0;
        }
    }
}