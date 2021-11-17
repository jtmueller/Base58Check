using Base58Check;
using NUnit.Framework;
using System.Collections;

namespace Tests;

public class EncodingTests
{
    // Test cases from https://github.com/bitcoin/bitcoin/blob/master/src/test/base58_tests.cpp
    private static readonly (string text, byte[] bytes)[] TEST_CASES = new[] {
        (string.Empty, Array.Empty<byte>()),
        ("1112", new byte[]{0x00, 0x00, 0x00, 0x01}),
        ("2g", new byte[]{0x61}),
        ("a3gV", new byte[]{0x62,0x62,0x62}),
        ("aPEr", new byte[]{0x63,0x63,0x63}),
        ("2cFupjhnEsSn59qHXstmK2ffpLv2", new byte[]{0x73,0x69,0x6d,0x70,0x6c,0x79,0x20,0x61,0x20,0x6c,0x6f,0x6e,0x67,0x20,0x73,0x74,0x72,0x69,0x6e,0x67}),
        ("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", new byte[]{0x00,0xeb,0x15,0x23,0x1d,0xfc,0xeb,0x60,0x92,0x58,0x86,0xb6,0x7d,0x06,0x52,0x99,0x92,0x59,0x15,0xae,0xb1,0x72,0xc0,0x66,0x47}),
        ("ABnLTmg", new byte[]{0x51,0x6b,0x6f,0xcd,0x0f}),
        ("3SEo3LWLoPntC", new byte[]{0xbf,0x4f,0x89,0x00,0x1e,0x67,0x02,0x74,0xdd}),
        ("3EFU7m", new byte[]{0x57,0x2e,0x47,0x94}),
        ("EJDM8drfXA6uyA", new byte[]{0xec,0xac,0x89,0xca,0xd9,0x39,0x23,0xc0,0x23,0x21}),
        ("Rt5zm", new byte[]{0x10,0xc8,0x51,0x1e}),
        ("1111111111", new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00})
    };

    // Example address from https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses
    private static readonly byte[] AddressBytes = new byte[] { 0x00, 0x01, 0x09, 0x66, 0x77, 0x60, 0x06, 0x95, 0x3D, 0x55, 0x67, 0x43, 0x9E, 0x5E, 0x39, 0xF8, 0x6A, 0x0D, 0x27, 0x3B, 0xEE };
    private const string ADDRESS_TEXT =        "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
    private const string BROKEN_ADDRESS_TEXT = "16UwLl9Risc3QfPqBUvKofHmBQ7wMtjvM";

    public static IEnumerable EncodeTestCases
    {
        get
        {
            foreach (var (text, bytes) in TEST_CASES)
            {
                yield return new TestCaseData(bytes).Returns(text);
            }
        }
    }

    public static IEnumerable DecodeTestCases
    {
        get
        {
            foreach (var (text, bytes) in TEST_CASES)
            {
                yield return new TestCaseData(text).Returns(bytes);
            }
        }
    }

    [TestCaseSource(typeof(EncodingTests), nameof(EncodeTestCases))]
    public string EncodePlain(byte[] bytes) => Base58Encoding.EncodePlain(bytes);

    [TestCaseSource(typeof(EncodingTests), nameof(DecodeTestCases))]
    public byte[] DecodePlain(string text) => Base58Encoding.DecodePlain(text);

    [Test]
    public void DecodeInvalidChar()
    {
        Assert.That(() => Base58Encoding.DecodePlain("ab0"),
            Throws.InstanceOf<FormatException>());
    }

    [Test]
    public void EncodeBitcoinAddress()
    {
        string actualText = Base58Encoding.EncodeWithChecksum(AddressBytes);
        Assert.AreEqual(ADDRESS_TEXT, actualText);
    }

    [Test]
    public void DecodeBitcoinAddress()
    {
        byte[] actualBytes = Base58Encoding.DecodeWithChecksum(ADDRESS_TEXT).ToArray();
        Assert.AreEqual(AddressBytes, actualBytes);
    }

    [Test]
    public void DecodeBrokenBitcoinAddress()
    {
        Assert.That(() => Base58Encoding.DecodeWithChecksum(BROKEN_ADDRESS_TEXT),
            Throws.InstanceOf<FormatException>());
    }

    [Test]
    public void TryDecodeBitcoinAddress()
    {
        Assert.True(Base58Encoding.TryDecodeWithChecksum(ADDRESS_TEXT, out var actualBytes));
        Assert.AreEqual(AddressBytes, actualBytes.ToArray());
    }

    [Test]
    public void TryDecodeBrokenBitcoinAddress() => Assert.False(Base58Encoding.TryDecodeWithChecksum(BROKEN_ADDRESS_TEXT, out var _));

    [Test]
    public void GuidEncodeDecode()
    {
        Span<char> chars = stackalloc char[Base58Encoding.MaxChars(16)];
        for (int i = 0; i < 16; i++)
        {
            var guid = i == 0 ? Guid.Empty : Guid.NewGuid();
            int written = Base58Encoding.EncodeGuid(guid, chars);

            //Console.WriteLine("{0:N} ({1})", guid, 32);
            //Console.WriteLine("{0} ({1})", chars[..written].ToString(), written);
            //Console.WriteLine();

            var decoded = Base58Encoding.DecodeGuid(chars[..written]);
            Assert.AreEqual(guid, decoded);
        }
    }

    [Test]
    public void GuidEncodeTryDecode()
    {
        Span<char> chars = stackalloc char[Base58Encoding.MaxChars(16)];
        for (int i = 0; i < 16; i++)
        {
            var guid = i == 0 ? Guid.Empty : Guid.NewGuid();
            int written = Base58Encoding.EncodeGuid(guid, chars);

            //Console.WriteLine("{0:N} ({1})", guid, 32);
            //Console.WriteLine("{0} ({1})", chars[..written].ToString(), written);
            //Console.WriteLine();

            Assert.IsTrue(Base58Encoding.TryDecodeGuid(chars[..written], out var decoded));
            Assert.AreEqual(guid, decoded);
        }
    }
}
