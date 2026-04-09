using System;
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;

// ReSharper disable MemberCanBePrivate.Global

namespace Base58Check;

/// <summary>
///     Base58Check Encoding / Decoding (Bitcoin-style)
/// </summary>
/// <remarks>
///     See here for more details: https://en.bitcoin.it/wiki/Base58Check_encoding
/// </remarks>
public static class Base58Encoding
{
    private const int ChecksumSize = 4;
    private const int HashBytes = 32;
    private const int GuidBytes = 16;

    private static readonly SearchValues<byte> ValidBase58Bytes = SearchValues.Create(DigitsByte);

    private static ReadOnlySpan<byte> DigitsByte => "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"u8;

    // Maps ASCII ordinal (0–127) → Base58 digit index (0–57), or 255 for invalid.
    // Inputs with bytes > 127 are rejected by ValidBase58Bytes before this table is consulted.
    private static ReadOnlySpan<byte> DecodeTable =>
    [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //   0– 15
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //  16– 31
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, //  32– 47
        255,   0,   1,   2,   3,   4,   5,   6,   7,   8, 255, 255, 255, 255, 255, 255, //  48– 63  '0'=invalid, '1'–'9'=0–8
        255,   9,  10,  11,  12,  13,  14,  15,  16, 255,  17,  18,  19,  20,  21, 255, //  64– 79  'A'–'H'=9–16, 'I'=invalid, 'J'–'N'=17–21, 'O'=invalid
         22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32, 255, 255, 255, 255, 255, //  80– 95  'P'–'Z'=22–32
        255,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43, 255,  44,  45,  46, //  96–111  'a'–'k'=33–43, 'l'=invalid, 'm'–'o'=44–46
         47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57, 255, 255, 255, 255, 255, // 112–127  'p'–'z'=47–57
    ];

    // ── Encode ───────────────────────────────────────────────────────────────────

    /// <summary>
    ///     Encodes data with a 4-byte checksum
    /// </summary>
    /// <param name="data">Data to be encoded</param>
    /// <returns></returns>
    public static string EncodeWithChecksum(ReadOnlySpan<byte> data)
    {
        var size = MaxCharsWithChecksum(data.Length);
        var pooled = size > 100 ? ArrayPool<byte>.Shared.Rent(size) : null;
        try
        {
            var result = pooled ?? stackalloc byte[size];
            var written = EncodeWithChecksum(data, result);
            return Encoding.UTF8.GetString(result[..written]);
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    /// <summary>
    ///     Encodes data with a 4-byte checksum.
    ///     Writes UTF-8 bytes to the destination span.
    /// </summary>
    /// <param name="data">Data to be encoded</param>
    /// <param name="destination">The destination span to write to.</param>
    /// <returns></returns>
    public static int EncodeWithChecksum(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        var size = data.Length + ChecksumSize;
        var pooled = size > 100 ? ArrayPool<byte>.Shared.Rent(size) : null;
        try
        {
            var dataWithChecksum = pooled ?? stackalloc byte[size];
            var written = AddCheckSum(data, dataWithChecksum);
            return EncodePlain(dataWithChecksum[..written], destination);
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    /// <summary>
    ///     Encodes data in plain Base58, without any checksum.
    /// </summary>
    /// <param name="data">The data to be encoded</param>
    /// <returns></returns>
    public static string EncodePlain(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return string.Empty;

        var maxChars = MaxChars(data.Length);
        var pooled = maxChars > 100 ? ArrayPool<byte>.Shared.Rent(maxChars) : null;
        try
        {
            var result = pooled ?? stackalloc byte[maxChars];
            var written = EncodePlain(data, result);
            return Encoding.UTF8.GetString(result[..written]);
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    /// <summary>
    ///     Encodes data in plain Base58, without any checksum.
    /// </summary>
    /// <param name="data">The data to be encoded</param>
    /// <param name="destination">The destination span to write to.</param>
    /// <returns>The actual number of characters written at the span indicated by the destination parameter.</returns>
    public static int EncodePlain(ReadOnlySpan<byte> data, Span<char> destination)
    {
        if (data.IsEmpty)
            return 0;

        var maxChars = MaxChars(data.Length);

        var pooled = maxChars > 100 ? ArrayPool<byte>.Shared.Rent(maxChars) : null;
        try
        {
            var result = pooled ?? stackalloc byte[maxChars];
            var written = EncodePlain(data, result);
            return Encoding.UTF8.GetChars(result[..written], destination);
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    /// <summary>
    ///     Encodes data in plain Base58, without any checksum.
    ///     Writes UTF-8 bytes to the destination span.
    /// </summary>
    /// <param name="data">The data to be encoded</param>
    /// <param name="destination">The destination span to write to.</param>
    /// <returns>Returns the number of bytes written to the destination span.</returns>
    public static int EncodePlain(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (data.IsEmpty)
            return 0;

        // Count leading zero bytes — each maps to a '1' character
        var leadingZeros = 0;
        while (leadingZeros < data.Length && data[leadingZeros] == 0)
            leadingZeros++;

        // Working buffer: base-58 digits stored least-significant-first
        var maxLen = MaxChars(data.Length);
        var pooled = maxLen > 100 ? ArrayPool<byte>.Shared.Rent(maxLen) : null;
        try
        {
            var digits = pooled is not null ? pooled.AsSpan(0, maxLen) : stackalloc byte[maxLen];
            digits.Clear();
            var digitsLen = 0;

            foreach (var b in data)
            {
                int carry = b;
                for (var i = 0; i < digitsLen; i++)
                {
                    carry += digits[i] * 256;
                    digits[i] = (byte)(carry % 58);
                    carry /= 58;
                }

                while (carry > 0)
                {
                    digits[digitsLen++] = (byte)(carry % 58);
                    carry /= 58;
                }
            }

            var alphabet = DigitsByte;
            const byte one = (byte)'1';
            var pos = 0;

            for (var i = 0; i < leadingZeros; i++)
                destination[pos++] = one;

            for (var i = digitsLen - 1; i >= 0; i--)
                destination[pos++] = alphabet[digits[i]];

            return pos;
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    // ── Guid ─────────────────────────────────────────────────────────────────────

    /// <summary>
    ///     Encodes a Guid to a 22-character Base-58 string.
    /// </summary>
    public static string EncodeGuid(Guid guid)
    {
        Span<byte> bytes = stackalloc byte[GuidBytes];
        guid.TryWriteBytes(bytes);
        return EncodePlain(bytes);
    }

    /// <summary>
    ///     Encodes a Guid to a 22-character Base-58 span.
    /// </summary>
    public static int EncodeGuid(Guid guid, Span<char> destination)
    {
        Span<byte> bytes = stackalloc byte[GuidBytes];
        guid.TryWriteBytes(bytes);
        return EncodePlain(bytes, destination);
    }

    /// <summary>
    ///     Encodes a Guid to a 22-character Base-58 span.
    /// </summary>
    public static int EncodeGuid(Guid guid, Span<byte> destination)
    {
        Span<byte> bytes = stackalloc byte[GuidBytes];
        guid.TryWriteBytes(bytes);
        return EncodePlain(bytes, destination);
    }

    /// <summary>
    ///     Decodes a Guid from a 22-character Base-58 string or span.
    /// </summary>
    public static Guid DecodeGuid(ReadOnlySpan<char> chars)
    {
        Span<byte> bytes = stackalloc byte[GuidBytes];
        var written = DecodePlain(chars, bytes);
        return written < bytes.Length
            ? throw new FormatException("Not enough bytes decoded for a Guid.")
            : new Guid(bytes);
    }

    /// <summary>
    ///     Decodes a Guid from a 22-character Base-58 string or span.
    /// </summary>
    public static Guid DecodeGuid(ReadOnlySpan<byte> chars)
    {
        Span<byte> bytes = stackalloc byte[GuidBytes];
        var written = DecodePlain(chars, bytes);
        return written < bytes.Length
            ? throw new FormatException("Not enough bytes decoded for a Guid.")
            : new Guid(bytes);
    }

    /// <summary>
    ///     Decodes a Guid from a 22-character Base-58 string or span.
    /// </summary>
    public static bool TryDecodeGuid(ReadOnlySpan<char> chars, out Guid decoded)
    {
        Span<byte> bytes = stackalloc byte[GuidBytes];
        var written = DecodePlain(chars, bytes);
        if (written < bytes.Length)
        {
            decoded = Guid.Empty;
            return false;
        }

        decoded = new Guid(bytes);
        return true;
    }

    /// <summary>
    ///     Decodes a Guid from a 22-character Base-58 string or span.
    /// </summary>
    public static bool TryDecodeGuid(ReadOnlySpan<byte> chars, out Guid decoded)
    {
        Span<byte> bytes = stackalloc byte[GuidBytes];
        var written = DecodePlain(chars, bytes);
        if (written < bytes.Length)
        {
            decoded = Guid.Empty;
            return false;
        }

        decoded = new Guid(bytes);
        return true;
    }

    // ── Sizing helpers ────────────────────────────────────────────────────────────

    /// <summary>
    ///     Gets the maximum number of characters that the given number of bytes can be encoded to.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int MaxChars(int byteCount)
    {
        return (int)Math.Ceiling(byteCount * (5.0 / 3.0));
    }

    /// <summary>
    ///     Gets the maximum number of characters that the given number of bytes can be encoded to, including checksum
    ///     characters.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int MaxCharsWithChecksum(int byteCount)
    {
        return MaxChars(byteCount + ChecksumSize);
    }

    /// <summary>
    ///     Gets the maximum number of bytes that the given number of characters can be decoded to.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int MaxBytes(int charCount)
    {
        return charCount;
        // worst case: all leading '1's → charCount zero bytes
    }

    /// <summary>
    ///     Gets the maximum number of bytes that the given number of characters can be decoded to, if the characters include a
    ///     checksum.
    /// </summary>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static int MaxBytesWithChecksum(int charCount)
    {
        return MaxBytes(charCount) - ChecksumSize;
    }

    // ── DecodeWithChecksum ────────────────────────────────────────────────────────

    /// <summary>
    ///     Decodes data in Base58Check format (with 4 byte checksum)
    /// </summary>
    /// <param name="chars">Data to be decoded</param>
    /// <param name="destination">The destination span to write to</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    public static int DecodeWithChecksum(ReadOnlySpan<char> chars, Span<byte> destination)
    {
        var bytesDecoded = DecodePlain(chars, destination);
        var dataWithoutCheckSum = VerifyAndRemoveCheckSum(destination[..bytesDecoded]);

        return dataWithoutCheckSum.IsEmpty
            ? throw new FormatException("Base58 checksum is invalid.")
            : dataWithoutCheckSum.Length;
    }

    /// <summary>
    ///     Decodes data in Base58Check format (with 4 byte checksum)
    /// </summary>
    /// <param name="chars">Data to be decoded</param>
    /// <param name="destination">The destination span to write to</param>
    /// <param name="bytesWritten">The number of bytes written</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    public static bool TryDecodeWithChecksum(ReadOnlySpan<char> chars, Span<byte> destination, out int bytesWritten)
    {
        if (!TryDecodePlain(chars, destination, out var bytesDecoded))
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
    ///     Decodes data in Base58Check format (with 4 byte checksum)
    /// </summary>
    /// <param name="chars">Chars to be decoded</param>
    /// <param name="destination">The destination span to write to</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    public static int DecodeWithChecksum(ReadOnlySpan<byte> chars, Span<byte> destination)
    {
        var bytesDecoded = DecodePlain(chars, destination);
        var dataWithoutCheckSum = VerifyAndRemoveCheckSum(destination[..bytesDecoded]);

        return dataWithoutCheckSum.IsEmpty
            ? throw new FormatException("Base58 checksum is invalid.")
            : dataWithoutCheckSum.Length;
    }

    /// <summary>
    ///     Decodes data in Base58Check format (with 4 byte checksum)
    /// </summary>
    /// <param name="chars">Data to be decoded</param>
    /// <param name="destination">The destination span to write to</param>
    /// <param name="bytesWritten">The number of bytes written</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    public static bool TryDecodeWithChecksum(ReadOnlySpan<byte> chars, Span<byte> destination, out int bytesWritten)
    {
        if (!TryDecodePlain(chars, destination, out var bytesDecoded))
        {
            bytesWritten = 0;
            return false;
        }

        var dataWithoutCheckSum = VerifyAndRemoveCheckSum(destination[..bytesDecoded]);

        if (dataWithoutCheckSum.IsEmpty)
        {
            bytesWritten = 0;
            destination[..bytesDecoded].Clear();
            return false;
        }

        bytesWritten = dataWithoutCheckSum.Length;
        return true;
    }

    // ── DecodePlain ───────────────────────────────────────────────────────────────

    /// <summary>
    ///     Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
    ///     Writes the decoded bytes to the destination span.
    /// </summary>
    /// <param name="chars">Data to be decoded</param>
    /// <param name="destination">The destination span to write to.</param>
    /// <returns>Returns the number of bytes written to the destination span</returns>
    public static int DecodePlain(ReadOnlySpan<char> chars, Span<byte> destination)
    {
        var maxByteCount = Encoding.UTF8.GetMaxByteCount(chars.Length);
        var pooled = maxByteCount > 100 ? ArrayPool<byte>.Shared.Rent(maxByteCount) : null;
        try
        {
            var bytes = pooled ?? stackalloc byte[maxByteCount];
            var written = Encoding.UTF8.GetBytes(chars, bytes);
            return DecodePlain(bytes[..written], destination);
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    /// <summary>
    ///     Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
    ///     Writes the decoded bytes to the destination span.
    /// </summary>
    /// <param name="chars">Data to be decoded</param>
    /// <param name="destination">The destination span to write to.</param>
    /// <param name="bytesWritten">The number of bytes written to the destination span</param>
    /// <returns>Returns the number of bytes written to the destination span</returns>
    public static bool TryDecodePlain(ReadOnlySpan<char> chars, Span<byte> destination, out int bytesWritten)
    {
        var maxByteCount = Encoding.UTF8.GetMaxByteCount(chars.Length);
        var pooled = maxByteCount > 100 ? ArrayPool<byte>.Shared.Rent(maxByteCount) : null;
        try
        {
            var bytes = pooled ?? stackalloc byte[maxByteCount];
            var written = Encoding.UTF8.GetBytes(chars, bytes);
            return TryDecodePlain(bytes[..written], destination, out bytesWritten);
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    /// <summary>
    ///     Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
    ///     Writes the decoded bytes to the destination span.
    /// </summary>
    /// <param name="data">Data to be decoded</param>
    /// <param name="destination">The destination span to write to.</param>
    /// <returns>Returns the number of bytes written to the destination span</returns>
    public static int DecodePlain(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (data.IsEmpty)
            return 0;

        var badIndex = data.IndexOfAnyExcept(ValidBase58Bytes);
        if (badIndex >= 0)
            throw new FormatException($"Invalid Base58 character '{(char)data[badIndex]}' at position {badIndex}.");

        return DecodeCore(data, destination);
    }

    /// <summary>
    ///     Decodes data in plain Base58 (as a UTF-8 byte span), without any checksum.
    ///     Writes the decoded bytes to the destination span.
    /// </summary>
    /// <param name="data">Data to be decoded</param>
    /// <param name="destination">The destination span to write to.</param>
    /// <param name="bytesWritten">The number of bytes written to the destination span</param>
    /// <returns>Returns the number of bytes written to the destination span</returns>
    public static bool TryDecodePlain(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)
    {
        if (data.IsEmpty)
        {
            bytesWritten = 0;
            return true;
        }

        if (data.IndexOfAnyExcept(ValidBase58Bytes) >= 0)
        {
            bytesWritten = 0;
            return false;
        }

        bytesWritten = DecodeCore(data, destination);
        return true;
    }

    // ── Obsolete overloads (use Span<byte> destination overloads instead) ─────────

    /// <summary>
    ///     Decodes data in Base58Check format (with 4 byte checksum)
    /// </summary>
    /// <param name="chars">Data to be decoded</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    [Obsolete("Use the Span<byte> destination overload instead: DecodeWithChecksum(ReadOnlySpan<char>, Span<byte>).", DiagnosticId = "B58_001")]
    public static ReadOnlySpan<byte> DecodeWithChecksum(ReadOnlySpan<char> chars)
    {
        var dest = new byte[MaxBytes(chars.Length)];
        int written = DecodeWithChecksum(chars, dest.AsSpan());
        return dest.AsSpan(0, written);
    }

    /// <summary>
    ///     Decodes data in Base58Check format (with 4 byte checksum)
    /// </summary>
    /// <param name="chars">Data to be decoded</param>
    /// <param name="data">Decoded data if valid, <see cref="ReadOnlySpan{byte}.Empty" /> if invalid.</param>
    /// <returns>Returns <c>true</c> if valid, otherwise <c>false</c>.</returns>
    [Obsolete("Use the Span<byte> destination overload instead: TryDecodeWithChecksum(ReadOnlySpan<char>, Span<byte>, out int).", DiagnosticId = "B58_001")]
    public static bool TryDecodeWithChecksum(ReadOnlySpan<char> chars, out ReadOnlySpan<byte> data)
    {
        var dest = new byte[MaxBytes(chars.Length)];
        if (!TryDecodeWithChecksum(chars, dest.AsSpan(), out int written))
        {
            data = default;
            return false;
        }
        data = dest.AsSpan(0, written);
        return true;
    }

    /// <summary>
    ///     Decodes data in plain Base58, without any checksum.
    /// </summary>
    /// <param name="data">Data to be decoded</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    [Obsolete("Use the Span<byte> destination overload instead: DecodePlain(ReadOnlySpan<char>, Span<byte>).",
        DiagnosticId = "B58_001")]
    public static byte[] DecodePlain(ReadOnlySpan<char> data)
    {
        if (data.IsEmpty)
            return [];

        var maxBytes = MaxBytes(data.Length);
        var pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            var buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            var written = DecodePlain(data, buf);
            return buf[..written].ToArray();
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    /// <summary>
    ///     Decodes data in plain Base58, without any checksum.
    /// </summary>
    /// <param name="data">Data to be decoded</param>
    /// <param name="result">The decoded data if valid</param>
    /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
    [Obsolete(
        "Use the Span<byte> destination overload instead: TryDecodePlain(ReadOnlySpan<char>, Span<byte>, out int).",
        DiagnosticId = "B58_001")]
    public static bool TryDecodePlain(ReadOnlySpan<char> data, out byte[] result)
    {
        if (data.IsEmpty)
        {
            result = [];
            return true;
        }

        var maxBytes = MaxBytes(data.Length);
        var pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            var buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            if (!TryDecodePlain(data, buf, out var written))
            {
                result = [];
                return false;
            }

            result = buf[..written].ToArray();
            return true;
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    // ── Private helpers ───────────────────────────────────────────────────────────

    // Preconditions: data is non-empty and contains only valid Base58 characters.
    private static int DecodeCore(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        const byte one = (byte)'1';
        var leadingZeros = 0;
        while (leadingZeros < data.Length && data[leadingZeros] == one)
            leadingZeros++;

        var maxLen = MaxBytes(data.Length);
        var pooled = maxLen > 100 ? ArrayPool<byte>.Shared.Rent(maxLen) : null;
        try
        {
            var bytes = pooled is not null ? pooled.AsSpan(0, maxLen) : stackalloc byte[maxLen];
            bytes.Clear();
            var bytesLen = 0;

            var table = DecodeTable;
            foreach (var b in data)
            {
                int carry = table[b];
                for (var i = 0; i < bytesLen; i++)
                {
                    carry += bytes[i] * 58;
                    bytes[i] = (byte)(carry & 0xFF);
                    carry >>= 8;
                }

                while (carry > 0)
                {
                    bytes[bytesLen++] = (byte)(carry & 0xFF);
                    carry >>= 8;
                }
            }

            destination[..leadingZeros].Clear();
            var significant = bytes[..bytesLen];
            significant.Reverse();
            significant.CopyTo(destination[leadingZeros..]);
            return leadingZeros + bytesLen;
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }

    private static int AddCheckSum(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Span<byte> checksum = stackalloc byte[ChecksumSize];
        if (!GetCheckSum(data, checksum)) throw new InvalidOperationException("Could not calculate checksum.");
        data.CopyTo(destination);
        checksum.CopyTo(destination[^ChecksumSize..]);
        return data.Length + ChecksumSize;
    }

    // Returns an empty span if the checksum is invalid
    private static ReadOnlySpan<byte> VerifyAndRemoveCheckSum(ReadOnlySpan<byte> data)
    {
        var result = data[..^ChecksumSize];
        var givenCheckSum = data[^ChecksumSize..];

        Span<byte> correctCheckSum = stackalloc byte[ChecksumSize];
        return GetCheckSum(result, correctCheckSum) && givenCheckSum.SequenceEqual(correctCheckSum)
            ? result
            : Span<byte>.Empty;
    }

    private static bool GetCheckSum(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Span<byte> hash = stackalloc byte[HashBytes * 2];
        var hash1 = hash[..HashBytes];
        var hash2 = hash[HashBytes..];

        if (!SHA256.TryHashData(data, hash1, out var written) ||
            !SHA256.TryHashData(hash1[..written], hash2, out written)) return false;
        hash2[..ChecksumSize].CopyTo(destination);
        return true;
    }
}
