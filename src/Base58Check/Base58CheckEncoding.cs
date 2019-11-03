using System;
using System.Numerics;
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
    public static class Base58CheckEncoding
    {
        private const int CHECKSUM_SIZE = 4;
        private const int HASH_BYTES = 32;
        private const string DIGITS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        /// <summary>
        /// Encodes data with a 4-byte checksum
        /// </summary>
        /// <param name="data">Data to be encoded</param>
        /// <returns></returns>
        public static string Encode(ReadOnlySpan<byte> data)
        {
            Span<byte> dataWithChecksum = data.Length > 100 
                ? new byte[data.Length + CHECKSUM_SIZE] 
                : stackalloc byte[data.Length + CHECKSUM_SIZE];
            _ = AddCheckSum(data, dataWithChecksum);
            return EncodePlain(dataWithChecksum);
        }

        /// <summary>
        /// Encodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">The data to be encoded</param>
        /// <returns></returns>
        public static string EncodePlain(ReadOnlySpan<byte> data)
        {
            // Decode byte[] to BigInteger
            var intData = BigInteger.Zero;
            for (int i = 0; i < data.Length; i++)
            {
                intData = (intData << 8) + data[i];
            }

            var digits = DIGITS.AsSpan();
            var fiftyEight = new BigInteger(58);

            // Encode BigInteger to Base58 string
            var result = new StringBuilder((int)(data.Length * (5.0 / 3.0)));
            while (intData > BigInteger.Zero)
            {
                int remainder = (int)(intData % fiftyEight);
                intData /= fiftyEight;
                result.Insert(0, digits[remainder]);
            }

            // Prepend `1` for each leading 0 byte
            for (int i = 0; i < data.Length && data[i] == 0; i++)
            {
                result.Insert(0, '1');
            }

            return result.ToString(); ;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static ReadOnlySpan<byte> Decode(ReadOnlySpan<char> data)
        {
            var dataWithCheckSum = DecodePlain(data);
            var dataWithoutCheckSum = VerifyAndRemoveCheckSum(dataWithCheckSum);

            if (dataWithoutCheckSum.IsEmpty)
            {
                throw new FormatException("Base58 checksum is invalid.");
            }

            return dataWithoutCheckSum;
        }

        /// <summary>
        /// Decodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static byte[] DecodePlain(ReadOnlySpan<char> data)
        {
            if (data.Length == 0)
                return Array.Empty<byte>();

            var digits = DIGITS.AsSpan();
            var fiftyEight = new BigInteger(58);

            // Decode Base58 string to BigInteger 
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                int digit = digits.IndexOf(data[i]);

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
