using Base58Check;
using System.Text;
using Xunit;

namespace Tests;

public class Base58ValueTests
{
    private static ReadOnlySpan<byte> SampleBytes => "simply a long string"u8;
    private const string SampleEncoded = "2cFupjhnEsSn59qHXstmK2ffpLv2";

    private static ReadOnlySpan<byte> AddressBytes =>
    [
        0x00, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E, 0x5E, 0x39, 0xF8, 0x6A, 0x0D,
        0x27, 0x3B, 0xEE
    ];

    // ── Factory: Encode ───────────────────────────────────────────────────────────

    [Fact]
    public void Encode_ToString_MatchesEncodePlain()
        => Assert.Equal(Base58Encoding.EncodePlain(SampleBytes), Base58Value.Encode(SampleBytes).ToString());

    [Fact]
    public void Encode_Length_MatchesToStringLength()
    {
        var v = Base58Value.Encode(SampleBytes);
        Assert.Equal(v.Length, v.ToString().Length);
    }

    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyValue()
    {
        var v = Base58Value.Encode([]);
        Assert.Equal(string.Empty, v.ToString());
        Assert.Equal(0, v.Length);
    }

    // ── HasValidChecksum ──────────────────────────────────────────────────────────

    [Fact]
    public void EncodeWithChecksum_ToString_MatchesEncodingMethod()
        => Assert.Equal(Base58Encoding.EncodeWithChecksum(AddressBytes), Base58Value.EncodeWithChecksum(AddressBytes).ToString());

    [Fact]
    public void EncodeWithChecksum_HasValidChecksum_IsTrue()
        => Assert.True(Base58Value.EncodeWithChecksum(AddressBytes).HasValidChecksum);

    [Fact]
    public void Encode_WithoutChecksum_HasValidChecksum_IsFalse()
        => Assert.False(Base58Value.Encode(SampleBytes).HasValidChecksum);

    // ── Factory: EncodeGuid ────────────────────────────────────────────────────

    [Fact]
    public void EncodeGuid_ToString_MatchesEncodingMethod()
    {
        var guid = Guid.NewGuid();
        Assert.Equal(Base58Encoding.EncodeGuid(guid), Base58Value.EncodeGuid(guid).ToString());
    }

    // ── Factory: Parse / TryParse ─────────────────────────────────────────────

    [Fact]
    public void Parse_CharSpan_ValidInput_ReturnsValue()
        => Assert.Equal(SampleEncoded, Base58Value.Parse(SampleEncoded.AsSpan()).ToString());

    [Fact]
    public void Parse_CharSpan_InvalidInput_ThrowsFormatException()
        => Assert.Throws<FormatException>(() => Base58Value.Parse("ab0".AsSpan()));

    [Fact]
    public void Parse_Utf8_ValidInput_ReturnsValue()
    {
        var utf8 = Encoding.UTF8.GetBytes(SampleEncoded);
        Assert.Equal(SampleEncoded, Base58Value.Parse(utf8.AsSpan()).ToString());
    }

    [Fact]
    public void Parse_Utf8_InvalidInput_ThrowsFormatException()
    {
        var utf8 = Encoding.UTF8.GetBytes("ab0");
        Assert.Throws<FormatException>(() => Base58Value.Parse(utf8.AsSpan()));
    }

    [Fact]
    public void TryParse_CharSpan_ValidInput_ReturnsTrueAndValue()
    {
        bool ok = Base58Value.TryParse(SampleEncoded.AsSpan(), out var value);
        Assert.True(ok);
        Assert.Equal(SampleEncoded, value.ToString());
    }

    [Fact]
    public void TryParse_CharSpan_InvalidInput_ReturnsFalse()
    {
        bool ok = Base58Value.TryParse("ab0".AsSpan(), out var value);
        Assert.False(ok);
        Assert.Equal(default, value);
    }

    [Fact]
    public void TryParse_Utf8_ValidInput_ReturnsTrueAndValue()
    {
        var utf8 = Encoding.UTF8.GetBytes(SampleEncoded);
        bool ok = Base58Value.TryParse(utf8.AsSpan(), out var value);
        Assert.True(ok);
        Assert.Equal(SampleEncoded, value.ToString());
    }

    [Fact]
    public void TryParse_Utf8_InvalidInput_ReturnsFalse()
    {
        var utf8 = Encoding.UTF8.GetBytes("ab0");
        bool ok = Base58Value.TryParse(utf8.AsSpan(), out var value);
        Assert.False(ok);
        Assert.Equal(default, value);
    }

    // ── Round-trip ────────────────────────────────────────────────────────────────

    [Fact]
    public void Encode_TryFormat_TryParse_Decode_RoundTrip()
    {
        var value = Base58Value.Encode(SampleBytes);
        var charBuf = new char[value.Length];
        Assert.True(value.TryFormat(charBuf.AsSpan(), out int written, default, null));
        Assert.True(Base58Value.TryParse(charBuf.AsSpan(0, written), out var parsed));
        var dest = new byte[Base58Encoding.MaxBytes(parsed.Length)];
        int bytesWritten = parsed.Decode(dest.AsSpan());
        Assert.Equal(SampleBytes, dest[..bytesWritten]);
    }

    // ── TryFormat ─────────────────────────────────────────────────────────────────

    [Fact]
    public void TryFormat_CharSpan_WritesExpected()
    {
        var value = Base58Value.Encode(SampleBytes);
        var dest = new char[value.Length];
        bool ok = value.TryFormat(dest.AsSpan(), out int written, default, null);
        Assert.True(ok);
        Assert.Equal(value.Length, written);
        Assert.Equal(SampleEncoded, new string(dest));
    }

    [Fact]
    public void TryFormat_CharSpan_TooSmall_ReturnsFalse()
    {
        var value = Base58Value.Encode(SampleBytes);
        var dest = new char[value.Length - 1];
        bool ok = value.TryFormat(dest.AsSpan(), out int written, default, null);
        Assert.False(ok);
        Assert.Equal(0, written);
    }

    [Fact]
    public void TryFormat_Utf8Span_WritesExpected()
    {
        var value = Base58Value.Encode(SampleBytes);
        var dest = new byte[value.Length];
        bool ok = value.TryFormat(dest.AsSpan(), out int written, default, null);
        Assert.True(ok);
        Assert.Equal(value.Length, written);
        Assert.Equal(Base58Encoding.EncodePlain(SampleBytes), Encoding.UTF8.GetString(dest));
    }

    [Fact]
    public void TryFormat_Utf8Span_TooSmall_ReturnsFalse()
    {
        var value = Base58Value.Encode(SampleBytes);
        var dest = new byte[value.Length - 1];
        bool ok = value.TryFormat(dest.AsSpan(), out int written, default, null);
        Assert.False(ok);
        Assert.Equal(0, written);
    }

    // ── Decode ────────────────────────────────────────────────────────────────────

    [Fact]
    public void Decode_RoundTripsWithEncode()
    {
        var value = Base58Value.Encode(SampleBytes);
        var dest = new byte[Base58Encoding.MaxBytes(value.Length)];
        int written = value.Decode(dest.AsSpan());
        Assert.Equal(SampleBytes, dest[..written]);
    }

    [Fact]
    public void TryDecode_RoundTripsWithEncode()
    {
        var value = Base58Value.Encode(SampleBytes);
        var dest = new byte[Base58Encoding.MaxBytes(value.Length)];
        bool ok = value.TryDecode(dest.AsSpan(), out int written);
        Assert.True(ok);
        Assert.Equal(SampleBytes, dest[..written]);
    }

    [Fact]
    public void DecodeWithChecksum_RoundTripsWithEncodeWithChecksum()
    {
        var value = Base58Value.EncodeWithChecksum(AddressBytes);
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(value.Length)];
        int written = value.DecodeWithChecksum(dest.AsSpan());
        Assert.Equal(AddressBytes, dest[..written]);
    }

    [Fact]
    public void TryDecodeWithChecksum_RoundTripsWithEncodeWithChecksum()
    {
        var value = Base58Value.EncodeWithChecksum(AddressBytes);
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(value.Length)];
        bool ok = value.TryDecodeWithChecksum(dest.AsSpan(), out int written);
        Assert.True(ok);
        Assert.Equal(AddressBytes, dest[..written]);
    }

    // ── Equality ──────────────────────────────────────────────────────────────────

    [Fact]
    public void Equals_SameEncodedData_ReturnsTrue()
    {
        var a = Base58Value.Encode(SampleBytes);
        var b = Base58Value.Encode(SampleBytes);
        Assert.Equal(a, b);
        Assert.True(a == b);
        Assert.False(a != b);
    }

    [Fact]
    public void Equals_DifferentEncodedData_ReturnsFalse()
    {
        var a = Base58Value.Encode(SampleBytes);
        var b = Base58Value.Encode([0x01, 0x02, 0x03]);
        Assert.NotEqual(a, b);
        Assert.False(a == b);
        Assert.True(a != b);
    }

    [Fact]
    public void GetHashCode_SameValues_AreEqual()
    {
        var a = Base58Value.Encode(SampleBytes);
        var b = Base58Value.Encode(SampleBytes);
        Assert.Equal(a.GetHashCode(), b.GetHashCode());
    }

    // ── CompareTo ─────────────────────────────────────────────────────────────────

    [Fact]
    public void CompareTo_SameValue_ReturnsZero()
    {
        var a = Base58Value.Encode(SampleBytes);
        var b = Base58Value.Encode(SampleBytes);
        Assert.Equal(0, a.CompareTo(b));
    }

    [Fact]
    public void CompareTo_OrderingConsistentWithOrdinalStringCompare()
    {
        var a = Base58Value.Encode([0x01]);
        var b = Base58Value.Encode([0xFF]);
        int expected = string.CompareOrdinal(a.ToString(), b.ToString());
        int actual = a.CompareTo(b);
        Assert.Equal(Math.Sign(expected), Math.Sign(actual));
    }
}
