using System.Buffers;
using System.Text;

namespace Base58Check;

/// <summary>
/// Represents a Base58-encoded value. Implements <see cref="ISpanFormattable"/> and
/// <see cref="IUtf8SpanFormattable"/> for zero-allocation formatting in logging,
/// JSON serialization, and other output pipelines.
/// </summary>
public readonly struct Base58Value
    : ISpanFormattable, IUtf8SpanFormattable,
      IEquatable<Base58Value>, IComparable<Base58Value>
{
    private readonly string? _encoded;

    private Base58Value(string encoded) => _encoded = encoded;

    /// <summary>Gets the number of Base58 characters in this value.</summary>
    public int Length => (_encoded ?? string.Empty).Length;

    /// <summary>
    /// Returns <see langword="true"/> if the encoded data contains a valid 4-byte checksum
    /// (i.e., it was produced by <see cref="EncodeWithChecksum"/>).
    /// </summary>
    public bool HasValidChecksum
    {
        get
        {
            var encoded = _encoded;
            if (string.IsNullOrEmpty(encoded)) return false;
            int maxBytes = Base58Encoding.MaxBytesWithChecksum(encoded.Length);
            byte[]? pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
            try
            {
                Span<byte> buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
                return Base58Encoding.TryDecodeWithChecksum(encoded.AsSpan(), buf, out _);
            }
            finally
            {
                if (pooled is not null) ArrayPool<byte>.Shared.Return(pooled);
            }
        }
    }

    // ── Factory: encoding ─────────────────────────────────────────────────────────

    /// <summary>Encodes <paramref name="data"/> as a plain Base58 value.</summary>
    public static Base58Value Encode(ReadOnlySpan<byte> data)
        => new(Base58Encoding.EncodePlain(data));

    /// <summary>Encodes <paramref name="data"/> with a 4-byte checksum.</summary>
    public static Base58Value EncodeWithChecksum(ReadOnlySpan<byte> data)
        => new(Base58Encoding.EncodeWithChecksum(data));

    /// <summary>Encodes a <see cref="Guid"/> as a Base58 value.</summary>
    public static Base58Value EncodeGuid(Guid guid)
        => new(Base58Encoding.EncodeGuid(guid));

    // ── Factory: parsing ──────────────────────────────────────────────────────────

    /// <summary>
    /// Parses an already-encoded Base58 char span.
    /// Throws <see cref="FormatException"/> if any character is invalid.
    /// </summary>
    public static Base58Value Parse(ReadOnlySpan<char> chars)
    {
        if (chars.IsEmpty) return new(string.Empty);
        int maxBytes = Base58Encoding.MaxBytes(chars.Length);
        byte[]? pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            Span<byte> buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            Base58Encoding.DecodePlain(chars, buf); // throws FormatException on invalid input
        }
        finally
        {
            if (pooled is not null) ArrayPool<byte>.Shared.Return(pooled);
        }
        return new(chars.ToString());
    }

    /// <summary>
    /// Parses an already-encoded Base58 UTF-8 byte span.
    /// Throws <see cref="FormatException"/> if any byte is invalid.
    /// </summary>
    public static Base58Value Parse(ReadOnlySpan<byte> utf8)
    {
        if (utf8.IsEmpty) return new(string.Empty);
        int maxBytes = Base58Encoding.MaxBytes(utf8.Length);
        byte[]? pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            Span<byte> buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            Base58Encoding.DecodePlain(utf8, buf); // throws FormatException on invalid input
        }
        finally
        {
            if (pooled is not null) ArrayPool<byte>.Shared.Return(pooled);
        }
        return new(Encoding.UTF8.GetString(utf8));
    }

    /// <summary>Attempts to parse an already-encoded Base58 char span.</summary>
    public static bool TryParse(ReadOnlySpan<char> chars, out Base58Value value)
    {
        if (chars.IsEmpty) { value = new(string.Empty); return true; }
        int maxBytes = Base58Encoding.MaxBytes(chars.Length);
        byte[]? pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            Span<byte> buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            if (!Base58Encoding.TryDecodePlain(chars, buf, out _)) { value = default; return false; }
        }
        finally
        {
            if (pooled is not null) ArrayPool<byte>.Shared.Return(pooled);
        }
        value = new(chars.ToString());
        return true;
    }

    /// <summary>Attempts to parse an already-encoded Base58 UTF-8 byte span.</summary>
    public static bool TryParse(ReadOnlySpan<byte> utf8, out Base58Value value)
    {
        if (utf8.IsEmpty) { value = new(string.Empty); return true; }
        int maxBytes = Base58Encoding.MaxBytes(utf8.Length);
        byte[]? pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            Span<byte> buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            if (!Base58Encoding.TryDecodePlain(utf8, buf, out _)) { value = default; return false; }
        }
        finally
        {
            if (pooled is not null) ArrayPool<byte>.Shared.Return(pooled);
        }
        value = new(Encoding.UTF8.GetString(utf8));
        return true;
    }

    // ── Decode ────────────────────────────────────────────────────────────────────

    /// <summary>Decodes to bytes. Throws <see cref="FormatException"/> if the value is invalid.</summary>
    public int Decode(Span<byte> destination)
        => Base58Encoding.DecodePlain((_encoded ?? string.Empty).AsSpan(), destination);

    /// <summary>Attempts to decode to bytes.</summary>
    public bool TryDecode(Span<byte> destination, out int bytesWritten)
        => Base58Encoding.TryDecodePlain((_encoded ?? string.Empty).AsSpan(), destination, out bytesWritten);

    /// <summary>Decodes with checksum verification. Throws <see cref="FormatException"/> if checksum is invalid.</summary>
    public int DecodeWithChecksum(Span<byte> destination)
        => Base58Encoding.DecodeWithChecksum((_encoded ?? string.Empty).AsSpan(), destination);

    /// <summary>Attempts to decode with checksum verification.</summary>
    public bool TryDecodeWithChecksum(Span<byte> destination, out int bytesWritten)
        => Base58Encoding.TryDecodeWithChecksum((_encoded ?? string.Empty).AsSpan(), destination, out bytesWritten);

    // ── ISpanFormattable ──────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public bool TryFormat(Span<char> destination, out int charsWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
    {
        var s = _encoded ?? string.Empty;
        if (destination.Length < s.Length) { charsWritten = 0; return false; }
        s.AsSpan().CopyTo(destination);
        charsWritten = s.Length;
        return true;
    }

    // ── IUtf8SpanFormattable ──────────────────────────────────────────────────────

    /// <inheritdoc/>
    public bool TryFormat(Span<byte> utf8Destination, out int bytesWritten, ReadOnlySpan<char> format, IFormatProvider? provider)
    {
        var s = _encoded ?? string.Empty;
        // Base58 is pure ASCII — UTF-8 byte length == char length
        if (utf8Destination.Length < s.Length) { bytesWritten = 0; return false; }
        Encoding.UTF8.GetBytes(s.AsSpan(), utf8Destination);
        bytesWritten = s.Length;
        return true;
    }

    // ── Object / equality ─────────────────────────────────────────────────────────

    /// <inheritdoc/>
    public override string ToString() => _encoded ?? string.Empty;

    /// <inheritdoc/>
    public string ToString(string? format, IFormatProvider? formatProvider) => _encoded ?? string.Empty;

    /// <inheritdoc/>
    public bool Equals(Base58Value other)
        => string.Equals(_encoded, other._encoded, StringComparison.Ordinal);

    /// <inheritdoc/>
    public override bool Equals(object? obj) => obj is Base58Value other && Equals(other);

    /// <inheritdoc/>
    public override int GetHashCode()
        => (_encoded ?? string.Empty).GetHashCode(StringComparison.Ordinal);

    /// <inheritdoc/>
    public int CompareTo(Base58Value other)
        => string.Compare(_encoded, other._encoded, StringComparison.Ordinal);

    /// <inheritdoc/>
    public static bool operator ==(Base58Value left, Base58Value right) => left.Equals(right);

    /// <inheritdoc/>
    public static bool operator !=(Base58Value left, Base58Value right) => !left.Equals(right);
}
