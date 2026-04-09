Base58Check
===========

Base58Check is a C# implementation of [Base58 Checked Encoding](https://en.bitcoin.it/wiki/Base58Check_encoding), based on a [public domain Gist](https://gist.github.com/CodesInChaos/3175971) by @CodesInChaos.

In short, Base58 is an encoding algorithm similar to Base64, removing certain characters that cause issues with URLs and cause visual confusion in certain fonts. Base58Check adds a 4-byte checksum to detect accidental data corruption. This checksum is not suitable for cryptographic validation.

## Installation

[NuGet Package](https://www.nuget.org/packages/Base58Check/)

Targets **net8.0** and **net10.0**.

## Public Interface

The library exposes two types:

- **`Base58Encoding`** — static class with low-level encode/decode methods
- **`Base58Value`** — readonly struct representing a validated Base58 string

---

### Base58Encoding

All methods use `ReadOnlySpan<byte>`/`Span<byte>` and avoid heap allocations. Buffers larger than 100 bytes fall back to `ArrayPool<byte>`.

#### Encoding

```csharp
// Plain Base58 (no checksum)
string        Base58Encoding.EncodePlain(ReadOnlySpan<byte> data)
int           Base58Encoding.EncodePlain(ReadOnlySpan<byte> data, Span<byte> destination)  // UTF-8 output
int           Base58Encoding.EncodePlain(ReadOnlySpan<byte> data, Span<char> destination)

// Base58Check (with 4-byte SHA256-derived checksum)
string        Base58Encoding.EncodeWithChecksum(ReadOnlySpan<byte> data)
int           Base58Encoding.EncodeWithChecksum(ReadOnlySpan<byte> data, Span<byte> destination)

// Guid → 22-character Base58 string
string        Base58Encoding.EncodeGuid(Guid guid)
int           Base58Encoding.EncodeGuid(Guid guid, Span<char> destination)
int           Base58Encoding.EncodeGuid(Guid guid, Span<byte> destination)  // UTF-8 output
```

#### Decoding

Throwing variants raise `FormatException` on invalid input or checksum mismatch. Try* variants return `false` instead.

```csharp
// Plain Base58 (no checksum)
int   Base58Encoding.DecodePlain(ReadOnlySpan<char> chars, Span<byte> destination)
int   Base58Encoding.DecodePlain(ReadOnlySpan<byte> utf8, Span<byte> destination)
bool  Base58Encoding.TryDecodePlain(ReadOnlySpan<char> chars, Span<byte> destination, out int bytesWritten)
bool  Base58Encoding.TryDecodePlain(ReadOnlySpan<byte> utf8, Span<byte> destination, out int bytesWritten)

// Base58Check (verifies checksum, strips it from output)
int   Base58Encoding.DecodeWithChecksum(ReadOnlySpan<char> chars, Span<byte> destination)
int   Base58Encoding.DecodeWithChecksum(ReadOnlySpan<byte> utf8, Span<byte> destination)
bool  Base58Encoding.TryDecodeWithChecksum(ReadOnlySpan<char> chars, Span<byte> destination, out int bytesWritten)
bool  Base58Encoding.TryDecodeWithChecksum(ReadOnlySpan<byte> utf8, Span<byte> destination, out int bytesWritten)

// Guid decoding
Guid  Base58Encoding.DecodeGuid(ReadOnlySpan<char> chars)
Guid  Base58Encoding.DecodeGuid(ReadOnlySpan<byte> utf8)
bool  Base58Encoding.TryDecodeGuid(ReadOnlySpan<char> chars, out Guid decoded)
bool  Base58Encoding.TryDecodeGuid(ReadOnlySpan<byte> utf8, out Guid decoded)
```

#### Buffer Sizing Helpers

```csharp
int  Base58Encoding.MaxChars(int byteCount)               // max encoded chars for N input bytes
int  Base58Encoding.MaxCharsWithChecksum(int byteCount)
int  Base58Encoding.MaxBytes(int charCount)               // max decoded bytes for N input chars
int  Base58Encoding.MaxBytesWithChecksum(int charCount)
```

---

### Base58Value

A readonly struct that holds a validated Base58 string. Implements `ISpanFormattable`, `IUtf8SpanFormattable`, `IEquatable<Base58Value>`, and `IComparable<Base58Value>`.

```csharp
// Create
Base58Value  Base58Value.Encode(ReadOnlySpan<byte> data)
Base58Value  Base58Value.EncodeWithChecksum(ReadOnlySpan<byte> data)
Base58Value  Base58Value.EncodeGuid(Guid guid)
Base58Value  Base58Value.Parse(ReadOnlySpan<char> chars)          // throws FormatException
Base58Value  Base58Value.Parse(ReadOnlySpan<byte> utf8)
bool         Base58Value.TryParse(ReadOnlySpan<char> chars, out Base58Value value)
bool         Base58Value.TryParse(ReadOnlySpan<byte> utf8, out Base58Value value)

// Inspect
int   value.Length           // number of Base58 characters
bool  value.HasValidChecksum // true if the value encodes a valid 4-byte checksum

// Decode
int   value.Decode(Span<byte> destination)
bool  value.TryDecode(Span<byte> destination, out int bytesWritten)
int   value.DecodeWithChecksum(Span<byte> destination)
bool  value.TryDecodeWithChecksum(Span<byte> destination, out int bytesWritten)
```

---

## License

This software is released to the public domain.

See LICENSE for more information.