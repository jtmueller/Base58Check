using System;
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

namespace Base58Check
{
    /// <summary>
    /// Base58Check Encoding / Decoding (Bitcoin-style)
    /// </summary>
    /// <remarks>
    /// See here for more details: https://en.bitcoin.it/wiki/Base58Check_encoding
    /// </remarks>
    public static class Base58Encoding
    {
        private const int CHECKSUM_SIZE = 4;
        private const int HASH_BYTES = 32;
        private const int GUID_BYTES = 16;
        private static readonly ReadOnlyMemory<byte> DIGITS_BYTE = Encoding.UTF8.GetBytes("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");

        // TODO: Better unit test coverage (maybe convert to xunit)

        /// <summary>
        /// Encodes data with a 4-byte checksum
        /// </summary>
        /// <param name="data">Data to be encoded</param>
        /// <returns></returns>
        public static string EncodeWithChecksum(ReadOnlySpan<byte> data)
        {
            byte[] result = ArrayPool<byte>.Shared.Rent(MaxCharsWithChecksum(data.Length));
            try
            {
                int written = EncodeWithChecksum(data, result);
                return Encoding.UTF8.GetString(result.AsSpan(..written));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(result);
            }
        }

        /// <summary>
        /// Encodes data with a 4-byte checksum.
        /// Writes UTF-8 bytes to the destination span.
        /// </summary>
        /// <param name="data">Data to be encoded</param>
        /// <param name="destination">The destination span to write to.</param>
        /// <returns></returns>
        public static int EncodeWithChecksum(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            byte[]? pooled = data.Length > 100 ? ArrayPool<byte>.Shared.Rent(data.Length + CHECKSUM_SIZE) : null;
            try
            {
                Span<byte> dataWithChecksum = pooled ?? stackalloc byte[data.Length + CHECKSUM_SIZE];
                _ = AddCheckSum(data, dataWithChecksum);
                return EncodePlain(dataWithChecksum, destination);
            }
            finally
            {
                if (pooled != null)
                {
                    ArrayPool<byte>.Shared.Return(pooled);
                }
            }
        }

        /// <summary>
        /// Encodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">The data to be encoded</param>
        /// <returns></returns>
        public static string EncodePlain(ReadOnlySpan<byte> data)
        {
            if (data.IsEmpty)
                return string.Empty;

            byte[] result = ArrayPool<byte>.Shared.Rent(MaxChars(data.Length));
            try
            {
                int written = EncodePlain(data, result);
                return Encoding.UTF8.GetString(result.AsSpan(..written));
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(result);
            }
        }

        /// <summary>
        /// Encodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">The data to be encoded</param>
        /// <param name="destination">The destination span to write to.</param>
        /// <returns></returns>
        public static int EncodePlain(ReadOnlySpan<byte> data, Span<char> destination)
        {
            if (data.IsEmpty)
                return 0;

            byte[] result = ArrayPool<byte>.Shared.Rent(MaxChars(data.Length));
            try
            {
                int written = EncodePlain(data, result);
                return Encoding.UTF8.GetChars(result.AsSpan(..written), destination);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(result);
            }
        }

        /// <summary>
        /// Encodes data in plain Base58, without any checksum.
        /// Writes UTF-8 bytes to the destination span.
        /// </summary>
        /// <param name="data">The data to be encoded</param>
        /// <param name="destination">The destination span to write to.</param>
        /// <returns>Returns the number of bytes written to the destination span.</returns>
        public static int EncodePlain(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            if (data.IsEmpty)
                return 0;

            // Decode bytes to BigInteger
            var intData = BigInteger.Zero;
            for (int i = 0; i < data.Length; i++)
            {
                intData = (intData << 8) | data[i];
            }

            var fiftyEight = new BigInteger(58);
            byte one = (byte)'1';

            // Encode BigInteger to Base58 char bytes
            int pos = 0;

            var digits = DIGITS_BYTE.Span;
            while (intData > BigInteger.Zero)
            {
                intData = BigInteger.DivRem(intData, fiftyEight, out var remainder);
                destination[pos++] = digits[(int)remainder];
            }

            // Append `1` for each leading 0 byte
            for (int i = 0; i < data.Length && data[i] == 0; i++)
            {
                destination[pos++] = one;
            }

            destination[..pos].Reverse();

            return pos;
        }

        /// <summary>
        /// Encodes a Guid to a 22-character Base-58 string.
        /// </summary>
        public static string EncodeGuid(Guid guid)
        {
            Span<byte> bytes = stackalloc byte[GUID_BYTES];
            guid.TryWriteBytes(bytes);
            return EncodePlain(bytes);
        }

        /// <summary>
        /// Encodes a Guid to a 22-character Base-58 span.
        /// </summary>
        public static int EncodeGuid(Guid guid, Span<char> destination)
        {
            Span<byte> bytes = stackalloc byte[GUID_BYTES];
            guid.TryWriteBytes(bytes);
            return EncodePlain(bytes, destination);
        }

        /// <summary>
        /// Decodes a Guid from a 22-character Base-58 string or span.
        /// </summary>
        public static Guid DecodeGuid(ReadOnlySpan<char> chars)
        {
            Span<byte> bytes = stackalloc byte[GUID_BYTES];
            int written = DecodePlain(chars, bytes);
            if (written < bytes.Length)
                throw new FormatException("Not enough bytes decoded for a Guid.");
            return new Guid(bytes);
        }

        /// <summary>
        /// Decodes a Guid from a 22-character Base-58 string or span.
        /// </summary>
        public static bool TryDecodeGuid(ReadOnlySpan<char> chars, out Guid decoded)
        {
            Span<byte> bytes = stackalloc byte[GUID_BYTES];
            int written = DecodePlain(chars, bytes);
            if (written < bytes.Length)
            {
                decoded = default;
                return false;
            }

            decoded = new Guid(bytes);
            return true;
        }

        /// <summary>
        /// Gets the maximum number of characters that the given number of bytes can be encoded to.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int MaxChars(int byteCount) => (int)Math.Ceiling(byteCount * (5.0 / 3.0));

        /// <summary>
        /// Gets the maximum number of characters that the given number of bytes can be encoded to, including checksum characters.
        /// </summary>
        public static int MaxCharsWithChecksum(int byteCount) => MaxChars(byteCount + CHECKSUM_SIZE);

        /// <summary>
        /// Gets the maximum number of bytes that the given number of characters can be decoded to.
        /// </summary>
        [MethodImpl(MethodImplOptions.AggressiveInlining)]
        public static int MaxBytes(int charCount) => (int)Math.Ceiling(charCount / (5.0 / 3.0));

        /// <summary>
        /// Gets the maximum number of bytes that the given number of characters can be decoded to, if the characters include a checksum.
        /// </summary>
        public static int MaxBytesWithChecksum(int charCount) => MaxBytes(charCount) - CHECKSUM_SIZE;

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="chars">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static ReadOnlySpan<byte> DecodeWithChecksum(ReadOnlySpan<char> chars)
        {
            var dataWithCheckSum = DecodePlain(chars);
            var dataWithoutCheckSum = VerifyAndRemoveCheckSum(dataWithCheckSum);

            if (dataWithoutCheckSum.IsEmpty)
            {
                throw new FormatException("Base58 checksum is invalid.");
            }

            return dataWithoutCheckSum;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="chars">Data to be decoded</param>
        /// <param name="data">Decoded data if valid, <see cref="ReadOnlySpan{byte}.Empty"/> if invalid.</param>
        /// <returns>Returns <c>true</c> if valid, otherwise <c>false</c>.</returns>
        public static bool TryDecodeWithChecksum(ReadOnlySpan<char> chars, out ReadOnlySpan<byte> data)
        {
            if (!TryDecodePlain(chars, out var dataWithCheckSum))
            {
                data = default;
                return false;
            }

            var dataWithoutCheckSum = VerifyAndRemoveCheckSum(dataWithCheckSum);

            if (dataWithoutCheckSum.IsEmpty)
            {
                data = default;
                return false;
            }

            data = dataWithoutCheckSum;
            return true;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="chars">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static int DecodeWithChecksum(ReadOnlySpan<char> chars, Span<byte> destination)
        {
            var bytesDecoded = DecodePlain(chars, destination);
            var dataWithoutCheckSum = VerifyAndRemoveCheckSum(destination[..bytesDecoded]);

            if (dataWithoutCheckSum.IsEmpty)
            {
                throw new FormatException("Base58 checksum is invalid.");
            }

            return dataWithoutCheckSum.Length;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="chars">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static bool TryDecodeWithChecksum(ReadOnlySpan<char> chars, Span<byte> destination, out int bytesWritten)
        {
            if (!TryDecodePlain(chars, destination, out int bytesDecoded))
            {
                bytesWritten = 0;
                return false;
            }

            var dataWithoutCheckSum = VerifyAndRemoveCheckSum(destination[..bytesDecoded]);

            if (dataWithoutCheckSum.IsEmpty)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = dataWithoutCheckSum.Length;
            return true;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static int DecodeWithChecksum(ReadOnlySpan<byte> chars, Span<byte> destination)
        {
            var bytesDecoded = DecodePlain(chars, destination);
            var dataWithoutCheckSum = VerifyAndRemoveCheckSum(destination[..bytesDecoded]);

            if (dataWithoutCheckSum.IsEmpty)
            {
                throw new FormatException("Base58 checksum is invalid.");
            }

            return dataWithoutCheckSum.Length;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static bool TryDecodeWithChecksum(ReadOnlySpan<byte> chars, Span<byte> destination, out int bytesWritten)
        {
            if (!TryDecodePlain(chars, destination, out int bytesDecoded))
            {
                bytesWritten = 0;
                return false;
            }

            var dataWithoutCheckSum = VerifyAndRemoveCheckSum(destination[..bytesDecoded]);

            if (dataWithoutCheckSum.IsEmpty)
            {
                bytesWritten = 0;
                return false;
            }

            bytesWritten = dataWithoutCheckSum.Length;
            return true;
        }

        /// <summary>
        /// Decodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static byte[] DecodePlain(ReadOnlySpan<char> data)
        {
            if (data.IsEmpty)
                return Array.Empty<byte>();

            var fiftyEight = new BigInteger(58);

            // Decode Base58 string to BigInteger 
            var digits = DIGITS_BYTE.Span;
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                int digit = digits.IndexOf((byte)data[i]);

                if (digit < 0)
                {
                    throw new FormatException($"Invalid Base58 character '{data[i]}' at position {i}.");
                }

                intData = intData * fiftyEight + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            int leadingZeroCount = 0;
            for (int i = 0; i < data.Length && data[i] == '1'; i++)
                leadingZeroCount++;

            if (intData.IsZero)
            {
                return leadingZeroCount == 0 ? Array.Empty<byte>() : new byte[leadingZeroCount];
            }

            int byteCount = intData.GetByteCount(isUnsigned: true);
            byte[] result = new byte[leadingZeroCount + byteCount];

            if (intData.TryWriteBytes(result.AsSpan(leadingZeroCount..), out int _, isUnsigned: true, isBigEndian: true))
            {
                return result;
            }

            throw new FormatException("Unable to decode the given Base58 string.");
        }

        /// <summary>
        /// Decodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static bool TryDecodePlain(ReadOnlySpan<char> data, out byte[] result)
        {
            if (data.IsEmpty)
            {
                result = Array.Empty<byte>();
                return true;
            }

            var fiftyEight = new BigInteger(58);

            // Decode Base58 string to BigInteger 
            var digits = DIGITS_BYTE.Span;
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                int digit = digits.IndexOf((byte)data[i]);

                if (digit < 0)
                {
                    result = Array.Empty<byte>();
                    return false;
                }

                intData = intData * fiftyEight + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            int leadingZeroCount = 0;
            for (int i = 0; i < data.Length && data[i] == '1'; i++)
                leadingZeroCount++;

            if (intData.IsZero)
            {
                result = leadingZeroCount == 0 ? Array.Empty<byte>() : new byte[leadingZeroCount];
                return true;
            }

            int byteCount = intData.GetByteCount(isUnsigned: true);
            result = new byte[leadingZeroCount + byteCount];

            return intData.TryWriteBytes(result.AsSpan(leadingZeroCount..), out int _, isUnsigned: true, isBigEndian: true);
        }

        /// <summary>
        /// Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
        /// Writes the decoded bytes to the destination span.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns the number of bytes written to the destination span</returns>
        public static int DecodePlain(ReadOnlySpan<char> chars, Span<byte> destination)
        {
            var maxByteCount = Encoding.UTF8.GetMaxByteCount(chars.Length);
            var pooled = maxByteCount > 100 ? ArrayPool<byte>.Shared.Rent(maxByteCount) : null;
            try
            {
                Span<byte> bytes = pooled ?? stackalloc byte[maxByteCount];
                int written = Encoding.UTF8.GetBytes(chars, bytes);
                return DecodePlain(bytes[..written], destination);
            }
            finally
            {
                if (pooled != null)
                    ArrayPool<byte>.Shared.Return(pooled);
            }
        }

        /// <summary>
        /// Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
        /// Writes the decoded bytes to the destination span.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns the number of bytes written to the destination span</returns>
        public static bool TryDecodePlain(ReadOnlySpan<char> chars, Span<byte> destination, out int bytesWritten)
        {
            var maxByteCount = Encoding.UTF8.GetMaxByteCount(chars.Length);
            var pooled = maxByteCount > 100 ? ArrayPool<byte>.Shared.Rent(maxByteCount) : null;
            try
            {
                Span<byte> bytes = pooled ?? stackalloc byte[maxByteCount];
                int written = Encoding.UTF8.GetBytes(chars, bytes);
                return TryDecodePlain(bytes[..written], destination, out bytesWritten);
            }
            finally
            {
                if (pooled != null)
                    ArrayPool<byte>.Shared.Return(pooled);
            }
        }

        /// <summary>
        /// Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
        /// Writes the decoded bytes to the destination span.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns the number of bytes written to the destination span</returns>
        public static int DecodePlain(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            if (data.IsEmpty)
                return 0;

            var fiftyEight = new BigInteger(58);
            byte one = (byte)'1';

            // Decode Base58 string to BigInteger 
            var digits = DIGITS_BYTE.Span;
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                int digit = digits.IndexOf(data[i]);

                if (digit < 0)
                {
                    throw new FormatException($"Invalid Base58 character '{(char)data[i]}' at position {i}.");
                }

                intData = intData * fiftyEight + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            int leadingZeroCount = 0;
            for (int i = 0; i < data.Length && data[i] == one; i++)
                leadingZeroCount++;

            if (leadingZeroCount > 0)
            {
                destination[..leadingZeroCount].Clear();
            }

            if (intData.IsZero)
            {
                return leadingZeroCount;
            }

            if (intData.TryWriteBytes(destination[leadingZeroCount..], out int written, isUnsigned: true, isBigEndian: true))
            {
                return written + leadingZeroCount;
            }

            throw new FormatException("Unable to decode the given Base58 string.");
        }

        /// <summary>
        /// Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
        /// Writes the decoded bytes to the destination span.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns the number of bytes written to the destination span</returns>
        public static bool TryDecodePlain(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
        {
            if (data.IsEmpty)
            {
                bytesWritten = 0;
                return true;
            }

            var fiftyEight = new BigInteger(58);
            byte one = (byte)'1';

            // Decode Base58 string to BigInteger 
            var digits = DIGITS_BYTE.Span;
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                int digit = digits.IndexOf(data[i]);

                if (digit < 0)
                {
                    bytesWritten = 0;
                    return false;
                }

                intData = intData * fiftyEight + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            int leadingZeroCount = 0;
            for (int i = 0; i < data.Length && data[i] == one; i++)
                leadingZeroCount++;

            if (leadingZeroCount > 0)
            {
                destination[..leadingZeroCount].Clear();
            }

            if (intData.IsZero)
            {
                bytesWritten = leadingZeroCount;
                return true;
            }

            if (intData.TryWriteBytes(destination[leadingZeroCount..], out int written, isUnsigned: true, isBigEndian: true))
            {
                bytesWritten = written + leadingZeroCount;
                return true;
            }

            bytesWritten = 0;
            return false;
        }

        private static int AddCheckSum(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            Span<byte> checksum = stackalloc byte[CHECKSUM_SIZE];
            if (GetCheckSum(data, checksum))
            {
                data.CopyTo(destination);
                checksum.CopyTo(destination[^CHECKSUM_SIZE..]);
                return data.Length + CHECKSUM_SIZE;
            }

            throw new InvalidOperationException("Could not calculate checksum.");
        }

        // Returns an empty span if the checksum is invalid
        private static ReadOnlySpan<byte> VerifyAndRemoveCheckSum(ReadOnlySpan<byte> data)
        {
            var result = data[..^CHECKSUM_SIZE];
            var givenCheckSum = data[^CHECKSUM_SIZE..];

            Span<byte> correctCheckSum = stackalloc byte[CHECKSUM_SIZE];
            if (GetCheckSum(result, correctCheckSum))
            {
                return givenCheckSum.SequenceEqual(correctCheckSum) ? result : Span<byte>.Empty;
            }

            return Span<byte>.Empty;
        }

        private static bool GetCheckSum(ReadOnlySpan<byte> data, Span<byte> destination)
        {
            using var sha = SHA256.Create();
            Span<byte> hash1 = stackalloc byte[HASH_BYTES];
            Span<byte> hash2 = stackalloc byte[HASH_BYTES];

            if (sha.TryComputeHash(data, hash1, out int written) &&
                sha.TryComputeHash(hash1[..written], hash2, out written))
            {
                hash2[..CHECKSUM_SIZE].CopyTo(destination);
                return true;
            }

            return false;
        }
    }
}
