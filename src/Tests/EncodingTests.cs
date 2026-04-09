using System.Text;
using Base58Check;
using Xunit;

namespace Tests;

public class EncodingTests
{
    private const string AddressText = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";

    private const string BrokenAddressText = "16UwLl9Risc3QfPqBUvKofHmBQ7wMtjvM";

    // Test vectors from https://github.com/bitcoin/bitcoin/blob/master/src/test/base58_tests.cpp
    private static readonly (string text, byte[] bytes)[] TestCases =
    [
        (string.Empty, []),
        ("1112", [0x00, 0x00, 0x00, 0x01]),
        ("2g", "a"u8.ToArray()),
        ("a3gV", "bbb"u8.ToArray()),
        ("aPEr", "ccc"u8.ToArray()),
        ("2cFupjhnEsSn59qHXstmK2ffpLv2", "simply a long string"u8.ToArray()),
        ("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L",
        [
            0x00, 0xeb, 0x15, 0x23, 0x1d, 0xfc, 0xeb, 0x60, 0x92, 0x58, 0x86, 0xb6, 0x7d, 0x06, 0x52, 0x99, 0x92, 0x59,
            0x15, 0xae, 0xb1, 0x72, 0xc0, 0x66, 0x47
        ]),
        ("ABnLTmg", [0x51, 0x6b, 0x6f, 0xcd, 0x0f]),
        ("3SEo3LWLoPntC", [0xbf, 0x4f, 0x89, 0x00, 0x1e, 0x67, 0x02, 0x74, 0xdd]),
        ("3EFU7m", [0x57, 0x2e, 0x47, 0x94]),
        ("EJDM8drfXA6uyA", [0xec, 0xac, 0x89, 0xca, 0xd9, 0x39, 0x23, 0xc0, 0x23, 0x21]),
        ("Rt5zm", [0x10, 0xc8, 0x51, 0x1e]),
        ("1111111111", "\0\0\0\0\0\0\0\0\0\0"u8.ToArray()),
    ];

    private static readonly byte[] AddressBytes =
    [
        0x00, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E, 0x5E, 0x39, 0xF8, 0x6A, 0x0D,
        0x27, 0x3B, 0xEE
    ];

    // ── Theory data ──────────────────────────────────────────────────────────────

    public static TheoryData<byte[], string> EncodeTestCases()
    {
        var data = new TheoryData<byte[], string>();
        foreach (var (text, bytes) in TestCases)
            data.Add(bytes, text);
        return data;
    }

    public static TheoryData<string, byte[]> DecodeTestCases()
    {
        var data = new TheoryData<string, byte[]>();
        foreach (var (text, bytes) in TestCases)
            data.Add(text, bytes);
        return data;
    }

    // ── EncodePlain ───────────────────────────────────────────────────────────────

    [Theory, MemberData(nameof(EncodeTestCases))]
    public void EncodePlain_String_ReturnsExpected(byte[] bytes, string expected)
        => Assert.Equal(expected, Base58Encoding.EncodePlain(bytes));

    [Theory, MemberData(nameof(EncodeTestCases))]
    public void EncodePlain_ToByteSpan_WritesExpectedUtf8(byte[] bytes, string expected)
    {
        var dest = new byte[Base58Encoding.MaxChars(bytes.Length)];
        int written = Base58Encoding.EncodePlain(bytes, dest.AsSpan());
        Assert.Equal(expected, Encoding.UTF8.GetString(dest, 0, written));
    }

    [Theory, MemberData(nameof(EncodeTestCases))]
    public void EncodePlain_ToCharSpan_WritesExpected(byte[] bytes, string expected)
    {
        var dest = new char[Base58Encoding.MaxChars(bytes.Length)];
        int written = Base58Encoding.EncodePlain(bytes, dest.AsSpan());
        Assert.Equal(expected, new string(dest, 0, written));
    }

    // ── DecodePlain ───────────────────────────────────────────────────────────────

    [Theory, MemberData(nameof(DecodeTestCases))]
    public void DecodePlain_CharSpan_WritesExpected(string text, byte[] expected)
    {
        var dest = new byte[Base58Encoding.MaxBytes(text.Length)];
        int written = Base58Encoding.DecodePlain(text.AsSpan(), dest.AsSpan());
        Assert.Equal(expected, dest[..written]);
    }

    [Theory, MemberData(nameof(DecodeTestCases))]
    public void DecodePlain_Utf8ByteSpan_WritesExpected(string text, byte[] expected)
    {
        var utf8 = Encoding.UTF8.GetBytes(text);
        var dest = new byte[Base58Encoding.MaxBytes(utf8.Length)];
        int written = Base58Encoding.DecodePlain(utf8.AsSpan(), dest.AsSpan());
        Assert.Equal(expected, dest[..written]);
    }

    [Theory, MemberData(nameof(DecodeTestCases))]
    public void TryDecodePlain_CharSpan_ReturnsTrueAndWritesExpected(string text, byte[] expected)
    {
        var dest = new byte[Base58Encoding.MaxBytes(text.Length)];
        bool ok = Base58Encoding.TryDecodePlain(text.AsSpan(), dest.AsSpan(), out int written);
        Assert.True(ok);
        Assert.Equal(expected, dest[..written]);
    }

    [Theory, MemberData(nameof(DecodeTestCases))]
    public void TryDecodePlain_Utf8ByteSpan_ReturnsTrueAndWritesExpected(string text, byte[] expected)
    {
        var utf8 = Encoding.UTF8.GetBytes(text);
        var dest = new byte[Base58Encoding.MaxBytes(utf8.Length)];
        bool ok = Base58Encoding.TryDecodePlain(utf8.AsSpan(), dest.AsSpan(), out int written);
        Assert.True(ok);
        Assert.Equal(expected, dest[..written]);
    }

    // ── Invalid character handling ─────────────────────────────────────────────

    [Theory]
    [InlineData("ab0")] // '0' not in Base58
    [InlineData("abO")] // 'O' not in Base58
    [InlineData("abI")] // 'I' not in Base58
    [InlineData("abl")] // 'l' not in Base58
    public void DecodePlain_Base58InvalidAscii_ThrowsFormatException(string input)
        => Assert.Throws<FormatException>(() =>
        {
            var dest = new byte[10];
            Base58Encoding.DecodePlain(input.AsSpan(), dest.AsSpan());
        });

    [Theory]
    [InlineData("ab0")]
    [InlineData("abO")]
    [InlineData("abI")]
    [InlineData("abl")]
    public void TryDecodePlain_InvalidInput_ReturnsFalse(string input)
    {
        var dest = new byte[10];
        Assert.False(Base58Encoding.TryDecodePlain(input.AsSpan(), dest.AsSpan(), out _));
    }

    [Fact]
    public void DecodePlain_NonAsciiBytes_ThrowsFormatException()
        => Assert.Throws<FormatException>(() =>
        {
            // 0xC3, 0xA4 are the UTF-8 encoding of 'ä' — both > 127, invalid in Base58
            var dest = new byte[10];
            Base58Encoding.DecodePlain("Aä"u8[..], dest.AsSpan());
        });

    [Fact]
    public void TryDecodePlain_NonAsciiBytes_ReturnsFalse()
    {
        var dest = new byte[10];
        Assert.False(Base58Encoding.TryDecodePlain("Aä"u8[..], dest.AsSpan(), out _));
    }

    [Theory]
    [InlineData(new byte[] { 0x61, 0x62, 0x30 })] // "ab0"
    [InlineData(new byte[] { 0x61, 0x62, 0x4F })] // "abO"
    [InlineData(new byte[] { 0x61, 0x62, 0x49 })] // "abI"
    [InlineData(new byte[] { 0x61, 0x62, 0x6C })] // "abl"
    public void TryDecodePlain_Utf8ByteSpan_InvalidBase58Ascii_ReturnsFalse(byte[] input)
    {
        var dest = new byte[10];
        Assert.False(Base58Encoding.TryDecodePlain(input.AsSpan(), dest.AsSpan(), out _));
    }

    // ── Edge cases ────────────────────────────────────────────────────────────────

    [Fact]
    public void EncodePlain_EmptyInput_ReturnsEmptyString()
        => Assert.Equal(string.Empty, Base58Encoding.EncodePlain(ReadOnlySpan<byte>.Empty));

    [Fact]
    public void DecodePlain_EmptyInput_WritesZeroBytes()
    {
        var dest = new byte[10];
        int written = Base58Encoding.DecodePlain(ReadOnlySpan<char>.Empty, dest.AsSpan());
        Assert.Equal(0, written);
    }

    [Fact]
    public void EncodePlain_AllZeroBytes_ReturnsAllOnes()
        => Assert.Equal("11111", Base58Encoding.EncodePlain(new byte[5]));

    [Fact]
    public void DecodePlain_AllOnes_ReturnsAllZeroBytes()
    {
        var dest = new byte[Base58Encoding.MaxBytes(5)];
        int written = Base58Encoding.DecodePlain("11111".AsSpan(), dest.AsSpan());
        Assert.Equal(5, written);
        Assert.All(dest[..written], b => Assert.Equal(0, b));
    }

    [Theory]
    [InlineData(new byte[] { 0x00 }, "1")]
    [InlineData(new byte[] { 0x01 }, "2")]
    [InlineData(new byte[] { 0xFF }, "5Q")]
    public void EncodePlain_SingleByte_ReturnsExpected(byte[] input, string expected)
        => Assert.Equal(expected, Base58Encoding.EncodePlain(input));

    // ── Bitcoin address (checksum) ─────────────────────────────────────────────

    [Fact]
    public void EncodeWithChecksum_BitcoinAddress_ReturnsExpected()
        => Assert.Equal(AddressText, Base58Encoding.EncodeWithChecksum(AddressBytes));

    [Fact]
    public void EncodeWithChecksum_ToByteSpan_WritesExpectedUtf8()
    {
        var dest = new byte[Base58Encoding.MaxCharsWithChecksum(AddressBytes.Length)];
        int written = Base58Encoding.EncodeWithChecksum(AddressBytes, dest.AsSpan());
        Assert.Equal(AddressText, Encoding.UTF8.GetString(dest, 0, written));
    }

    [Fact]
    public void DecodeWithChecksum_CharSpan_ReturnsExpected()
    {
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(AddressText.Length)];
        var written = Base58Encoding.DecodeWithChecksum(AddressText.AsSpan(), dest.AsSpan());
        Assert.Equal(AddressBytes, dest[..written]);
    }

    [Fact]
    public void DecodeWithChecksum_BrokenAddress_ThrowsFormatException()
        => Assert.Throws<FormatException>(() =>
        {
            var dest = new byte[Base58Encoding.MaxBytesWithChecksum(BrokenAddressText.Length)];
            Base58Encoding.DecodeWithChecksum(BrokenAddressText.AsSpan(), dest.AsSpan());
        });

    [Fact]
    public void TryDecodeWithChecksum_CharSpan_ValidAddress_ReturnsTrueAndExpected()
    {
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(AddressText.Length)];
        var ok = Base58Encoding.TryDecodeWithChecksum(AddressText.AsSpan(), dest.AsSpan(), out int written);
        Assert.True(ok);
        Assert.Equal(AddressBytes, dest[..written]);
    }

    [Fact]
    public void TryDecodeWithChecksum_CharSpan_BrokenAddress_ReturnsFalse()
    {
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(BrokenAddressText.Length)];
        Assert.False(Base58Encoding.TryDecodeWithChecksum(BrokenAddressText.AsSpan(), dest.AsSpan(), out _));
    }

    [Fact]
    public void DecodeWithChecksum_Utf8ByteSpan_ValidAddress_ReturnsExpected()
    {
        var utf8 = Encoding.UTF8.GetBytes(AddressText);
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(AddressText.Length)];
        var written = Base58Encoding.DecodeWithChecksum(utf8.AsSpan(), dest.AsSpan());
        Assert.Equal(AddressBytes, dest[..written]);
    }

    [Fact]
    public void TryDecodeWithChecksum_Utf8ByteSpan_ValidAddress_ReturnsTrueAndExpected()
    {
        var utf8 = Encoding.UTF8.GetBytes(AddressText);
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(AddressText.Length)];
        var ok = Base58Encoding.TryDecodeWithChecksum(utf8.AsSpan(), dest.AsSpan(), out int written);
        Assert.True(ok);
        Assert.Equal(AddressBytes, dest[..written]);
    }

    [Fact]
    public void TryDecodeWithChecksum_Utf8ByteSpan_BrokenAddress_ReturnsFalse()
    {
        var utf8 = Encoding.UTF8.GetBytes(BrokenAddressText);
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(BrokenAddressText.Length)];
        Assert.False(Base58Encoding.TryDecodeWithChecksum(utf8.AsSpan(), dest.AsSpan(), out _));
    }

    // ── Guid ──────────────────────────────────────────────────────────────────────

    [Fact]
    public void EncodeGuid_String_DecodesBack()
    {
        var guid = Guid.NewGuid();
        var encoded = Base58Encoding.EncodeGuid(guid);
        Assert.Equal(guid, Base58Encoding.DecodeGuid(encoded.AsSpan()));
    }

    [Fact]
    public void EncodeGuid_CharSpan_DecodeGuid_RoundTrips()
    {
        var chars = new char[Base58Encoding.MaxChars(16)];
        // 16 iterations: Guid.Empty + 15 random GUIDs (16 chosen to exercise all byte positions)
        for (var i = 0; i < 16; i++)
        {
            var guid = i == 0 ? Guid.Empty : Guid.NewGuid();
            int written = Base58Encoding.EncodeGuid(guid, chars.AsSpan());
            Assert.Equal(guid, Base58Encoding.DecodeGuid(chars.AsSpan(0, written)));
        }
    }

    [Fact]
    public void EncodeGuid_CharSpan_TryDecodeGuid_RoundTrips()
    {
        var chars = new char[Base58Encoding.MaxChars(16)];
        // 16 iterations: Guid.Empty + 15 random GUIDs (16 chosen to exercise all byte positions)
        for (var i = 0; i < 16; i++)
        {
            var guid = i == 0 ? Guid.Empty : Guid.NewGuid();
            var written = Base58Encoding.EncodeGuid(guid, chars.AsSpan());
            Assert.True(Base58Encoding.TryDecodeGuid(chars.AsSpan(0, written), out var decoded));
            Assert.Equal(guid, decoded);
        }
    }

    [Fact]
    public void EncodeGuid_ByteSpan_TryDecodeGuid_RoundTrips()
    {
        var guid = Guid.NewGuid();
        var dest = new byte[Base58Encoding.MaxChars(16)];
        var written = Base58Encoding.EncodeGuid(guid, dest.AsSpan());
        Assert.True(Base58Encoding.TryDecodeGuid(dest.AsSpan(0, written), out var decoded));
        Assert.Equal(guid, decoded);
    }

    [Fact]
    public void EncodeGuid_MaxValueGuid_RoundTrips()
    {
        var guid = new Guid(new byte[]
            { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF });
        var encoded = Base58Encoding.EncodeGuid(guid);
        Assert.Equal(guid, Base58Encoding.DecodeGuid(encoded.AsSpan()));
    }

    // ── Obsolete overload regression ──────────────────────────────────────────────

#pragma warning disable B58_001
    [Fact]
    public void DecodePlain_ObsoleteByteArray_StillReturnsCorrectBytes()
        => Assert.Equal("a"u8.ToArray(), Base58Encoding.DecodePlain("2g".AsSpan()));

    [Fact]
    public void TryDecodePlain_ObsoleteByteArray_ReturnsTrueAndCorrectBytes()
    {
        var ok = Base58Encoding.TryDecodePlain("2g".AsSpan(), out byte[] result);
        Assert.True(ok);
        Assert.Equal("a"u8.ToArray(), result);
    }
#pragma warning restore B58_001
}