# Base58Check — .NET 10 Modernization Design

**Date:** 2026-04-07  
**Branch:** feat/modernize  
**Status:** Approved

---

## Overview

Modernize the Base58Check library and test suite to target `net8.0;net10.0`, replace the `BigInteger`-based algorithm with a zero-allocation carry-propagation approach, introduce a `Base58Value` struct implementing `IUtf8SpanFormattable`, migrate tests from NUnit 3 to xUnit v3 with expanded coverage, and add a BenchmarkDotNet project.

---

## Section 1: Project Structure

### Library (`Base58Check/Base58Check.csproj`)

- `TargetFrameworks`: `net8.0;net10.0` — drops `netstandard2.1` and `net6.0`
- `LangVersion`: `latest` — C# 13 features (`[]` collection expressions, `params ReadOnlySpan<T>`, etc.)
- Remove `EnforceCodeStyleInBuild=False`; add `<TreatWarningsAsErrors>true</TreatWarningsAsErrors>`
- Drop the `#if NET6_0_OR_GREATER` / `#else` block in `GetCheckSum` — the modern `SHA256.TryHashData` path becomes the only path

### Tests (`Tests/Tests.csproj`)

- `TargetFramework`: `net10.0`
- Replace NUnit 3 packages with: `xunit` (v3 latest), `xunit.runner.visualstudio` (latest), `Microsoft.NET.Test.Sdk` (latest)
- `LangVersion`: `latest`

### New: `Benchmarks/Benchmarks.csproj`

- `TargetFramework`: `net10.0`
- `LangVersion`: `latest`
- References `BenchmarkDotNet` and the library project
- Not included in the solution's default build configuration (set `<IsPublishable>false</IsPublishable>`, run explicitly)

---

## Section 2: Algorithm — Carry-Propagation Replacement for BigInteger

### Motivation

The current `EncodePlain` converts input bytes to a `BigInteger`, then repeatedly divides by 58. The current `DecodePlain` accumulates a `BigInteger` by multiplying by 58. Both operations allocate on the heap for any non-trivial input size. The replacement eliminates all `BigInteger` usage.

### Encode (bytes → Base58 characters)

1. Stack-allocate a working buffer sized `MaxChars(data.Length)`.
2. For each input byte (left to right), multiply existing working-buffer digits by 256, add the new byte, propagate carries mod 58.
3. Count leading zero bytes in the input; prepend that many `'1'` characters.
4. Map remaining digits through `DigitsByte` alphabet.

For inputs up to ~100 bytes, the working buffer fits on the stack (threshold already established in the codebase).

### Decode (Base58 characters → bytes)

1. Use `SearchValues<byte>` to fast-reject any input byte outside the valid Base58 ASCII range in a single SIMD pass.
2. For each character, look up its digit value (0–57) via a 128-entry `static ReadOnlySpan<byte> DecodeTable` literal (invalid entries = 255). Zero heap allocation — stored in the assembly's read-only data segment.
3. Multiply the accumulator (base-256 working buffer) by 58 and add the digit value, propagating carries.
4. Count leading `'1'` characters; prepend that many zero bytes to the output.

### Decode Table

A 128-byte `static ReadOnlySpan<byte>` literal mapping ASCII ordinal → Base58 index (0–57), or 255 for invalid characters. Covers the full ASCII range; inputs with bytes > 127 are rejected by the `SearchValues` pre-check.

### SearchValues usage

```csharp
private static readonly SearchValues<byte> ValidBase58Bytes =
    SearchValues.Create("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"u8);
```

Used at the top of all decode paths: if `data.IndexOfAnyExcept(ValidBase58Bytes) >= 0`, return false / throw immediately.

---

## Section 3: API — `Base58Value` and Deprecations

### Deprecated overloads

The following overloads on `Base58Encoding` are marked `[Obsolete("Use the Span<byte> destination overload instead.", DiagnosticId = "B58_001")]`:

- `DecodePlain(ReadOnlySpan<char>) → byte[]`
- `TryDecodePlain(ReadOnlySpan<char>, out byte[]) → bool`

No overloads are removed. All deprecated overloads remain functionally correct.

### New type: `Base58Value`

A `readonly struct` in the `Base58Check` namespace.

```csharp
public readonly struct Base58Value
    : ISpanFormattable, IUtf8SpanFormattable,
      IEquatable<Base58Value>, IComparable<Base58Value>
{
    // Factory — encoding
    public static Base58Value Encode(ReadOnlySpan<byte> data);
    public static Base58Value EncodeWithChecksum(ReadOnlySpan<byte> data);
    public static Base58Value EncodeGuid(Guid guid);

    // Factory — parsing already-encoded strings
    public static Base58Value Parse(ReadOnlySpan<char> chars);           // throws on invalid
    public static Base58Value Parse(ReadOnlySpan<byte> utf8);            // throws on invalid
    public static bool TryParse(ReadOnlySpan<char> chars, out Base58Value value);
    public static bool TryParse(ReadOnlySpan<byte> utf8, out Base58Value value);

    // Properties
    public int Length { get; }
    public bool HasValidChecksum { get; }

    // Decode back to bytes
    public int Decode(Span<byte> destination);                           // throws if invalid
    public bool TryDecode(Span<byte> destination, out int bytesWritten);
    public int DecodeWithChecksum(Span<byte> destination);               // throws if checksum invalid
    public bool TryDecodeWithChecksum(Span<byte> destination, out int bytesWritten);

    // ISpanFormattable
    public bool TryFormat(Span<char> destination, out int charsWritten,
        ReadOnlySpan<char> format, IFormatProvider? provider);

    // IUtf8SpanFormattable
    public bool TryFormat(Span<byte> utf8Destination, out int bytesWritten,
        ReadOnlySpan<char> format, IFormatProvider? provider);

    // Object
    public override string ToString();

    // IEquatable<Base58Value>
    public bool Equals(Base58Value other);
    public override bool Equals(object? obj);
    public override int GetHashCode();
    public static bool operator ==(Base58Value left, Base58Value right);
    public static bool operator !=(Base58Value left, Base58Value right);

    // IComparable<Base58Value>
    public int CompareTo(Base58Value other);
}
```

**Internal storage:** A `string` holding the encoded characters, allocated once at construction. `TryFormat` writes directly from this string — no re-encoding per call.

**Example usage:**

```csharp
// Zero-allocation formatting into an HTTP response / log / URL buffer
Base58Value txId = Base58Value.EncodeWithChecksum(transactionBytes);
logger.LogInformation("Transaction committed: {TxId}", txId);  // ISpanFormattable — no temp string

// Utf8JsonWriter / IBufferWriter<byte> pipeline
Base58Value id = Base58Value.EncodeGuid(guid);
writer.WriteStringValue(id);  // IUtf8SpanFormattable — no intermediate string

// URL building
Span<char> url = stackalloc char[64];
$"/api/resource/{id}".TryCopyTo(url);
```

---

## Section 4: Testing

### xUnit v3 migration patterns

| NUnit 3 | xUnit v3 |
|---|---|
| `[TestCaseSource(nameof(X))]` | `[Theory, MemberData(nameof(X))]` with `TheoryData<>` |
| `Assert.That(x, Is.EqualTo(y))` | `Assert.Equal(y, x)` |
| `Assert.That(() => f(), Throws.InstanceOf<T>())` | `Assert.Throws<T>(() => f())` |
| `[Test]` | `[Fact]` |

### Existing tests (migrated)

- `EncodePlain` round-trips (13 Bitcoin test vectors)
- `DecodePlain` round-trips (same vectors)
- `DecodeInvalidChar` — throws `FormatException`
- `EncodeBitcoinAddress` / `DecodeBitcoinAddress` / `DecodeBrokenBitcoinAddress`
- `TryDecodeBitcoinAddress` / `TryDecodeBrokenBitcoinAddress`
- `GuidEncodeDecode` / `GuidEncodeTryDecode`

### New tests (expanded coverage)

**Span-destination encode overloads:**
- `EncodePlain(data, Span<byte>)` — returns correct byte count, writes correct UTF-8
- `EncodeWithChecksum(data, Span<byte>)` — same

**UTF-8 decode overloads:**
- `DecodePlain(ReadOnlySpan<byte>, Span<byte>)` — all 13 test vectors
- `TryDecodePlain(ReadOnlySpan<byte>, Span<byte>, out int)` — valid and invalid inputs

**`TryDecodeWithChecksum` span overloads (currently untested):**
- `TryDecodeWithChecksum(ReadOnlySpan<char>, Span<byte>, out int)` — valid, invalid checksum
- `TryDecodeWithChecksum(ReadOnlySpan<byte>, Span<byte>, out int)` — valid, invalid checksum

**Edge cases:**
- Empty input → empty output (encode and decode)
- All-zero bytes (e.g. `new byte[10]`) → all `'1'` characters
- Single byte (each of 0x00, 0x01, 0xFF)
- Max-size Guid input

**Invalid character rejection:**
- Non-ASCII bytes (> 127)
- Base58-invalid ASCII: `'0'`, `'O'`, `'I'`, `'l'`
- Mixed valid/invalid

**`Base58Value` tests:**
- `Encode` → `TryFormat(Span<char>)` → `TryParse` → `Decode` round-trip
- `Encode` → `TryFormat(Span<byte>)` → UTF-8 bytes match `EncodePlain` result
- `EncodeWithChecksum` → `HasValidChecksum` is true
- `Parse` with invalid input throws `FormatException`
- `TryParse` with invalid input returns false, out value is default
- `ToString()` matches `Base58Encoding.EncodePlain`
- `Equals` / `==` / `!=` / `GetHashCode` consistency
- `CompareTo` ordering

**Obsolete overload regression:**
- `DecodePlain(ReadOnlySpan<char>) → byte[]` still returns correct results (with `#pragma warning disable B58_001`)

### Benchmarks (`Benchmarks/Benchmarks.csproj`)

All benchmarks use `[MemoryDiagnoser]` to track allocations.

| Benchmark | Input sizes |
|---|---|
| `EncodePlain` | 16 B, 25 B, 100 B |
| `DecodePlain` | 16 B, 25 B, 100 B |
| `EncodeWithChecksum` | 16 B, 25 B, 100 B |
| `DecodeWithChecksum` | 16 B, 25 B, 100 B |
| `EncodeGuid` | — |
| `DecodeGuid` | — |
| `Base58Value.Encode` + `TryFormat` vs `EncodePlain` → `string` | 16 B, 25 B |

---

## Out of Scope

- Removing deprecated overloads (can be done in a future major version bump)
- Source generator or `CompiledRegex`-style optimizations
- `IBufferWriter<byte>` extension methods (could be added later)
- NuGet package publishing / version bump (separate concern)
