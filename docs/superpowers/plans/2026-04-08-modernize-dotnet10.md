# Base58Check .NET 10 Modernization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Modernize the Base58Check library to target net8.0/net10.0, replace BigInteger with a zero-allocation carry-propagation algorithm, introduce `Base58Value` with `IUtf8SpanFormattable`, migrate tests to xUnit v3 with expanded coverage, and add a BenchmarkDotNet project.

**Architecture:** The single static class `Base58Encoding` retains its existing span-based API; the BigInteger encode/decode loops are replaced by carry-propagation over stack-allocated working buffers, with `SearchValues<byte>` for fast invalid-input rejection. A new `Base58Value` readonly struct wraps the encoded string and implements `ISpanFormattable`/`IUtf8SpanFormattable` for zero-allocation formatting pipelines.

**Tech Stack:** .NET 8/10, C# latest (13+), xUnit v3, BenchmarkDotNet, `System.Buffers` (`SearchValues`, `ArrayPool`), `SHA256.TryHashData`

**Spec:** `docs/superpowers/specs/2026-04-07-modernize-dotnet10-design.md`

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Modify | `src/Base58Check/Base58Check.csproj` | Targets, lang version, analyzers |
| Modify | `src/Base58Check/Base58Encoding.cs` | Algorithm, deprecations, remove `#if` blocks |
| Create | `src/Base58Check/Base58Value.cs` | New `readonly struct` |
| Modify | `src/Tests/Tests.csproj` | xUnit v3 packages, net10.0 |
| Modify | `src/Tests/EncodingTests.cs` | xUnit migration + expanded coverage |
| Create | `src/Tests/Base58ValueTests.cs` | Tests for `Base58Value` |
| Create | `src/Benchmarks/Benchmarks.csproj` | Benchmark console app |
| Create | `src/Benchmarks/Base58Benchmarks.cs` | BenchmarkDotNet benchmark class |

---

### Task 1: Update project files

**Files:**
- Modify: `src/Base58Check/Base58Check.csproj`
- Modify: `src/Tests/Tests.csproj`

- [ ] **Step 1: Replace `src/Base58Check/Base58Check.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">

  <PropertyGroup>
    <TargetFrameworks>net8.0;net10.0</TargetFrameworks>
    <LangVersion>latest</LangVersion>
    <Nullable>enable</Nullable>
    <ImplicitUsings>enable</ImplicitUsings>
    <EnableNETAnalyzers>True</EnableNETAnalyzers>
    <AnalysisLevel>latest</AnalysisLevel>
    <TreatWarningsAsErrors>true</TreatWarningsAsErrors>
  </PropertyGroup>

  <PropertyGroup>
    <AssemblyTitle>Base58Check</AssemblyTitle>
    <Product>Base58Check</Product>
    <Copyright>Public Domain</Copyright>
    <AssemblyVersion>0.4.0.0</AssemblyVersion>
    <FileVersion>0.4.0.0</FileVersion>
    <GeneratePackageOnBuild>false</GeneratePackageOnBuild>
    <Version>0.4.0</Version>
    <Authors>adamcaudill, jtmueller</Authors>
    <PackageProjectUrl>https://github.com/adamcaudill/Base58Check</PackageProjectUrl>
    <Description>Base58Check is a C# implementation of Base58 Checked Encoding</Description>
    <PackageTags>Base58 Bitcoin IPFS "Checked Encoding"</PackageTags>
    <PackageReleaseNotes>Targets net8.0 and net10.0; zero-allocation carry-propagation algorithm; Base58Value with IUtf8SpanFormattable.</PackageReleaseNotes>
    <PackageLicenseFile>LICENSE</PackageLicenseFile>
  </PropertyGroup>

  <ItemGroup>
    <None Include="..\..\LICENSE">
      <Pack>True</Pack>
      <PackagePath></PackagePath>
    </None>
  </ItemGroup>

</Project>
```

- [ ] **Step 2: Replace `src/Tests/Tests.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <AssemblyTitle>Tests</AssemblyTitle>
    <IsPackable>false</IsPackable>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\Base58Check\Base58Check.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 3: Add xUnit v3 packages to the test project**

```bash
cd /Users/jtm/dev/Base58Check
dotnet add src/Tests/Tests.csproj package xunit.v3
dotnet add src/Tests/Tests.csproj package xunit.runner.visualstudio
dotnet add src/Tests/Tests.csproj package Microsoft.NET.Test.Sdk
```

- [ ] **Step 4: Build the library only (tests will fail until Task 5)**

```bash
cd /Users/jtm/dev/Base58Check
dotnet build src/Base58Check/Base58Check.csproj
```

Expected: Build succeeds with no errors.

- [ ] **Step 5: Commit**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Base58Check/Base58Check.csproj src/Tests/Tests.csproj
git commit -m "chore: target net8.0/net10.0; migrate test project to xUnit v3"
```

---

### Task 2: Remove `#if NET6_0_OR_GREATER` preprocessor block

**Files:**
- Modify: `src/Base58Check/Base58Encoding.cs` (last ~30 lines)

The bottom of the file has two `GetCheckSum` implementations: one for .NET 6+ using `SHA256.TryHashData`, and a fallback using `SHA256.Create()`. Since we now target net8.0+ only, the fallback is dead code. Remove the `#if` / `#else` / `#endif` and keep only the modern path.

- [ ] **Step 1: Replace the conditional block**

Find this section at the bottom of `src/Base58Check/Base58Encoding.cs`:

```csharp
#if NET6_0_OR_GREATER

    private static bool GetCheckSum(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Span<byte> hash = stackalloc byte[HashBytes * 2];
        var hash1 = hash[..HashBytes];
        var hash2 = hash[HashBytes..];

        if (!SHA256.TryHashData(data, hash1, out int written) ||
            !SHA256.TryHashData(hash1[..written], hash2, out written)) return false;
        hash2[..ChecksumSize].CopyTo(destination);
        return true;

    }

#else

    private static bool GetCheckSum(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        using var sha = SHA256.Create();
        Span<byte> hash = stackalloc byte[HashBytes * 2];
        var hash1 = hash[..HashBytes];
        var hash2 = hash[HashBytes..];

        if (!sha.TryComputeHash(data, hash1, out int written) ||
            !sha.TryComputeHash(hash1[..written], hash2, out written)) return false;
        hash2[..ChecksumSize].CopyTo(destination);
        return true;
    }

#endif
```

Replace with:

```csharp
    private static bool GetCheckSum(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Span<byte> hash = stackalloc byte[HashBytes * 2];
        var hash1 = hash[..HashBytes];
        var hash2 = hash[HashBytes..];

        if (!SHA256.TryHashData(data, hash1, out int written) ||
            !SHA256.TryHashData(hash1[..written], hash2, out written)) return false;
        hash2[..ChecksumSize].CopyTo(destination);
        return true;
    }
```

- [ ] **Step 2: Build to verify**

```bash
cd /Users/jtm/dev/Base58Check
dotnet build src/Base58Check/Base58Check.csproj
```

Expected: Build succeeds.

- [ ] **Step 3: Commit**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Base58Check/Base58Encoding.cs
git commit -m "chore: remove NET6_0_OR_GREATER preprocessor guards"
```

---

### Task 3: Replace BigInteger with carry-propagation algorithm

**Files:**
- Modify: `src/Base58Check/Base58Encoding.cs`

Replace all `BigInteger`-based encode and decode logic with a carry-propagation algorithm. The four methods to change are:
- `EncodePlain(ReadOnlySpan<byte>, Span<byte>)` — core encode (all other encode overloads call this)
- `DecodePlain(ReadOnlySpan<byte>, Span<byte>)` — core byte-span decode
- `TryDecodePlain(ReadOnlySpan<byte>, Span<byte>, out int)` — try-pattern byte-span decode
- `DecodePlain(ReadOnlySpan<char>)` — char overload (has its own BigInteger loop)
- `TryDecodePlain(ReadOnlySpan<char>, out byte[])` — char try-overload (has its own BigInteger loop)

**How carry-propagation encode works:** maintain a working buffer of base-58 digits (least-significant first). For each input byte, multiply existing digits by 256 and add the byte, propagating carries mod 58. Prepend `'1'` for each leading zero byte, then write digits in reverse (most-significant first).

**How carry-propagation decode works:** maintain a working buffer of base-256 bytes (least-significant first). For each input Base58 character, look up its digit value (0–57) via a 128-entry decode table, multiply existing bytes by 58 and add the value, propagating carries. Prepend zero bytes for leading `'1'` characters, then write bytes in reverse.

- [ ] **Step 1: Remove `using System.Numerics;`**

At the top of `src/Base58Check/Base58Encoding.cs`, find:

```csharp
using System.Buffers;
using System.Numerics;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
```

Replace with:

```csharp
using System.Buffers;
using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
```

- [ ] **Step 2: Add `SearchValues` and `DecodeTable` after the existing `DigitsByte` property**

Find `private static ReadOnlySpan<byte> DigitsByte => ...` (line 23) and add directly after it:

```csharp
    private static readonly SearchValues<byte> ValidBase58Bytes =
        SearchValues.Create("123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"u8);

    // Maps ASCII ordinal (0–127) → Base58 digit index (0–57), or 255 for invalid.
    // Inputs with bytes > 127 are rejected by ValidBase58Bytes before this table is consulted.
    private static ReadOnlySpan<byte> DecodeTable =>
    [
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 0–15
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 16–31
        255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, // 32–47
        255,   0,   1,   2,   3,   4,   5,   6,   7,   8, 255, 255, 255, 255, 255, 255, // 48–63  '0'=invalid, '1'–'9'=0–8
        255,   9,  10,  11,  12,  13,  14,  15,  16, 255,  17,  18,  19,  20,  21, 255, // 64–79  'A'–'H'=9–16, 'I'=invalid, 'J'–'N'=17–21, 'O'=invalid
         22,  23,  24,  25,  26,  27,  28,  29,  30,  31,  32, 255, 255, 255, 255, 255, // 80–95  'P'–'Z'=22–32
        255,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,  43, 255,  44,  45,  46, // 96–111 'a'–'k'=33–43, 'l'=invalid, 'm'–'o'=44–46
         47,  48,  49,  50,  51,  52,  53,  54,  55,  56,  57, 255, 255, 255, 255, 255, // 112–127 'p'–'z'=47–57
    ];
```

- [ ] **Step 3: Replace `EncodePlain(ReadOnlySpan<byte>, Span<byte>)` body**

Find `public static int EncodePlain(ReadOnlySpan<byte> data, Span<byte> destination)` — the overload whose destination is `Span<byte>` (around line 132). Replace its entire body:

```csharp
    public static int EncodePlain(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (data.IsEmpty)
            return 0;

        // Count leading zero bytes — each maps to a '1' character
        int leadingZeros = 0;
        while (leadingZeros < data.Length && data[leadingZeros] == 0)
            leadingZeros++;

        // Working buffer: base-58 digits stored least-significant-first
        int maxLen = MaxChars(data.Length);
        byte[]? pooled = maxLen > 100 ? ArrayPool<byte>.Shared.Rent(maxLen) : null;
        try
        {
            Span<byte> digits = pooled is not null ? pooled.AsSpan(0, maxLen) : stackalloc byte[maxLen];
            digits.Clear();
            int digitsLen = 0;

            foreach (byte b in data)
            {
                int carry = b;
                for (int i = 0; i < digitsLen; i++)
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
            int pos = 0;

            for (int i = 0; i < leadingZeros; i++)
                destination[pos++] = one;

            for (int i = digitsLen - 1; i >= 0; i--)
                destination[pos++] = alphabet[digits[i]];

            return pos;
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }
```

- [ ] **Step 4: Replace `DecodePlain(ReadOnlySpan<byte>, Span<byte>)` body**

Find `public static int DecodePlain(ReadOnlySpan<byte> data, Span<byte> destination)` (around line 553). Replace its entire body:

```csharp
    public static int DecodePlain(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (data.IsEmpty)
            return 0;

        int badIndex = data.IndexOfAnyExcept(ValidBase58Bytes);
        if (badIndex >= 0)
            throw new FormatException($"Invalid Base58 character '{(char)data[badIndex]}' at position {badIndex}.");

        const byte one = (byte)'1';
        int leadingZeros = 0;
        while (leadingZeros < data.Length && data[leadingZeros] == one)
            leadingZeros++;

        int maxLen = MaxBytes(data.Length);
        byte[]? pooled = maxLen > 100 ? ArrayPool<byte>.Shared.Rent(maxLen) : null;
        try
        {
            Span<byte> bytes = pooled is not null ? pooled.AsSpan(0, maxLen) : stackalloc byte[maxLen];
            bytes.Clear();
            int bytesLen = 0;

            var table = DecodeTable;
            foreach (byte b in data)
            {
                int carry = table[b];
                for (int i = 0; i < bytesLen; i++)
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
            int pos = leadingZeros;
            for (int i = bytesLen - 1; i >= 0; i--)
                destination[pos++] = bytes[i];

            return pos;
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }
```

- [ ] **Step 5: Replace `TryDecodePlain(ReadOnlySpan<byte>, Span<byte>, out int)` body**

Find `public static bool TryDecodePlain(ReadOnlySpan<byte> data, Span<byte> destination, out int bytesWritten)` (around line 607). Replace its entire body:

```csharp
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

        const byte one = (byte)'1';
        int leadingZeros = 0;
        while (leadingZeros < data.Length && data[leadingZeros] == one)
            leadingZeros++;

        int maxLen = MaxBytes(data.Length);
        byte[]? pooled = maxLen > 100 ? ArrayPool<byte>.Shared.Rent(maxLen) : null;
        try
        {
            Span<byte> bytes = pooled is not null ? pooled.AsSpan(0, maxLen) : stackalloc byte[maxLen];
            bytes.Clear();
            int bytesLen = 0;

            var table = DecodeTable;
            foreach (byte b in data)
            {
                int carry = table[b];
                for (int i = 0; i < bytesLen; i++)
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
            int pos = leadingZeros;
            for (int i = bytesLen - 1; i >= 0; i--)
                destination[pos++] = bytes[i];

            bytesWritten = pos;
            return true;
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }
```

- [ ] **Step 6: Replace `DecodePlain(ReadOnlySpan<char>)` body to remove its own BigInteger loop**

Find `public static byte[] DecodePlain(ReadOnlySpan<char> data)` (around line 408). Replace its entire body with a delegation to the span overload:

```csharp
    public static byte[] DecodePlain(ReadOnlySpan<char> data)
    {
        if (data.IsEmpty)
            return [];

        int maxBytes = MaxBytes(data.Length);
        byte[]? pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            Span<byte> buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            int written = DecodePlain(data, buf);
            return buf[..written].ToArray();
        }
        finally
        {
            if (pooled is not null)
                ArrayPool<byte>.Shared.Return(pooled);
        }
    }
```

- [ ] **Step 7: Replace `TryDecodePlain(ReadOnlySpan<char>, out byte[])` body**

Find `public static bool TryDecodePlain(ReadOnlySpan<char> data, out byte[] result)` (around line 454). Replace its entire body:

```csharp
    public static bool TryDecodePlain(ReadOnlySpan<char> data, out byte[] result)
    {
        if (data.IsEmpty)
        {
            result = [];
            return true;
        }

        int maxBytes = MaxBytes(data.Length);
        byte[]? pooled = maxBytes > 100 ? ArrayPool<byte>.Shared.Rent(maxBytes) : null;
        try
        {
            Span<byte> buf = pooled is not null ? pooled.AsSpan(0, maxBytes) : stackalloc byte[maxBytes];
            if (!TryDecodePlain(data, buf, out int written))
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
```

- [ ] **Step 8: Build the library**

```bash
cd /Users/jtm/dev/Base58Check
dotnet build src/Base58Check/Base58Check.csproj
```

Expected: Build succeeds with zero warnings.

- [ ] **Step 9: Commit**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Base58Check/Base58Encoding.cs
git commit -m "perf: replace BigInteger with carry-propagation; add SearchValues decode validation"
```

---

### Task 4: Deprecate byte[]-returning overloads

**Files:**
- Modify: `src/Base58Check/Base58Encoding.cs`

- [ ] **Step 1: Add `[Obsolete]` to `DecodePlain(ReadOnlySpan<char>)`**

Find `public static byte[] DecodePlain(ReadOnlySpan<char> data)` and insert the attribute on the line above:

```csharp
    [Obsolete("Use the Span<byte> destination overload instead: DecodePlain(ReadOnlySpan<char>, Span<byte>).", DiagnosticId = "B58_001")]
    public static byte[] DecodePlain(ReadOnlySpan<char> data)
```

- [ ] **Step 2: Add `[Obsolete]` to `TryDecodePlain(ReadOnlySpan<char>, out byte[])`**

Find `public static bool TryDecodePlain(ReadOnlySpan<char> data, out byte[] result)` and insert:

```csharp
    [Obsolete("Use the Span<byte> destination overload instead: TryDecodePlain(ReadOnlySpan<char>, Span<byte>, out int).", DiagnosticId = "B58_001")]
    public static bool TryDecodePlain(ReadOnlySpan<char> data, out byte[] result)
```

- [ ] **Step 3: Build to confirm no new warnings**

```bash
cd /Users/jtm/dev/Base58Check
dotnet build src/Base58Check/Base58Check.csproj
```

Expected: Build succeeds. `[Obsolete]` only fires at call sites, not at the method definition.

- [ ] **Step 4: Commit**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Base58Check/Base58Encoding.cs
git commit -m "feat: deprecate byte[]-returning DecodePlain/TryDecodePlain overloads (B58_001)"
```

---

### Task 5: Migrate `EncodingTests.cs` to xUnit v3 with expanded coverage

**Files:**
- Modify: `src/Tests/EncodingTests.cs`

Replace the entire file. NUnit patterns used:
- `[Test]` → `[Fact]`
- `[TestCaseSource]` + `IEnumerable<TestCaseData>` + `.Returns(value)` → `[Theory]` + `[MemberData(nameof(X))]` + `TheoryData<TInput, TExpected>`; expected value becomes a parameter
- `Assert.That(actual, Is.EqualTo(expected))` → `Assert.Equal(expected, actual)`
- `Assert.That(() => f(), Throws.InstanceOf<T>())` → `Assert.Throws<T>(() => f())`

New tests cover: all span encode overloads, UTF-8 decode overloads, `TryDecodeWithChecksum` span overloads, edge cases, invalid character variants, Guid overloads, and obsolete overload regression.

- [ ] **Step 1: Write the new `src/Tests/EncodingTests.cs`**

```csharp
using Base58Check;
using System.Text;
using Xunit;

namespace Tests;

public class EncodingTests
{
    // Test vectors from https://github.com/bitcoin/bitcoin/blob/master/src/test/base58_tests.cpp
    private static readonly (string text, byte[] bytes)[] TestCases =
    [
        (string.Empty, []),
        ("1112", [0x00, 0x00, 0x00, 0x01]),
        ("2g", "a"u8.ToArray()),
        ("a3gV", "bbb"u8.ToArray()),
        ("aPEr", "ccc"u8.ToArray()),
        ("2cFupjhnEsSn59qHXstmK2ffpLv2", "simply a long string"u8.ToArray()),
        ("1NS17iag9jJgTHD1VXjvLCEnZuQ3rJDE9L", [0x00,0xeb,0x15,0x23,0x1d,0xfc,0xeb,0x60,0x92,0x58,0x86,0xb6,0x7d,0x06,0x52,0x99,0x92,0x59,0x15,0xae,0xb1,0x72,0xc0,0x66,0x47]),
        ("ABnLTmg", [0x51,0x6b,0x6f,0xcd,0x0f]),
        ("3SEo3LWLoPntC", [0xbf,0x4f,0x89,0x00,0x1e,0x67,0x02,0x74,0xdd]),
        ("3EFU7m", [0x57,0x2e,0x47,0x94]),
        ("EJDM8drfXA6uyA", [0xec,0xac,0x89,0xca,0xd9,0x39,0x23,0xc0,0x23,0x21]),
        ("Rt5zm", [0x10,0xc8,0x51,0x1e]),
        ("1111111111", [0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00]),
    ];

    private static readonly byte[] AddressBytes = [0x00,0x01,0x09,0x66,0x77,0x60,0x06,0x95,0x3D,0x55,0x67,0x43,0x9E,0x5E,0x39,0xF8,0x6A,0x0D,0x27,0x3B,0xEE];
    private const string AddressText    = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";
    private const string BrokenAddressText = "16UwLl9Risc3QfPqBUvKofHmBQ7wMtjvM";

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

    [Fact]
    public void DecodePlain_InvalidChar_ThrowsFormatException()
        => Assert.Throws<FormatException>(() =>
        {
            var dest = new byte[10];
            Base58Encoding.DecodePlain("ab0".AsSpan(), dest.AsSpan());
        });

    [Theory]
    [InlineData("ab0")]  // '0' not in Base58
    [InlineData("abO")]  // 'O' not in Base58
    [InlineData("abI")]  // 'I' not in Base58
    [InlineData("abl")]  // 'l' not in Base58
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
            Base58Encoding.DecodePlain(new byte[] { 0x41, 0xC3, 0xA4 }.AsSpan(), dest.AsSpan());
        });

    [Fact]
    public void TryDecodePlain_NonAsciiBytes_ReturnsFalse()
    {
        var dest = new byte[10];
        Assert.False(Base58Encoding.TryDecodePlain(new byte[] { 0x41, 0xC3, 0xA4 }.AsSpan(), dest.AsSpan(), out _));
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
        int written = Base58Encoding.DecodeWithChecksum(AddressText.AsSpan(), dest.AsSpan());
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
        bool ok = Base58Encoding.TryDecodeWithChecksum(AddressText.AsSpan(), dest.AsSpan(), out int written);
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
        int written = Base58Encoding.DecodeWithChecksum(utf8.AsSpan(), dest.AsSpan());
        Assert.Equal(AddressBytes, dest[..written]);
    }

    [Fact]
    public void TryDecodeWithChecksum_Utf8ByteSpan_ValidAddress_ReturnsTrueAndExpected()
    {
        var utf8 = Encoding.UTF8.GetBytes(AddressText);
        var dest = new byte[Base58Encoding.MaxBytesWithChecksum(AddressText.Length)];
        bool ok = Base58Encoding.TryDecodeWithChecksum(utf8.AsSpan(), dest.AsSpan(), out int written);
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
        string encoded = Base58Encoding.EncodeGuid(guid);
        Assert.Equal(guid, Base58Encoding.DecodeGuid(encoded.AsSpan()));
    }

    [Fact]
    public void EncodeGuid_CharSpan_DecodeGuid_RoundTrips()
    {
        var chars = new char[Base58Encoding.MaxChars(16)];
        for (int i = 0; i < 16; i++)
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
        for (int i = 0; i < 16; i++)
        {
            var guid = i == 0 ? Guid.Empty : Guid.NewGuid();
            int written = Base58Encoding.EncodeGuid(guid, chars.AsSpan());
            Assert.True(Base58Encoding.TryDecodeGuid(chars.AsSpan(0, written), out var decoded));
            Assert.Equal(guid, decoded);
        }
    }

    [Fact]
    public void EncodeGuid_ByteSpan_DecodeGuid_RoundTrips()
    {
        var guid = Guid.NewGuid();
        var dest = new byte[Base58Encoding.MaxChars(16)];
        int written = Base58Encoding.EncodeGuid(guid, dest.AsSpan());
        Assert.True(Base58Encoding.TryDecodeGuid(dest.AsSpan(0, written), out var decoded));
        Assert.Equal(guid, decoded);
    }

    // ── Obsolete overload regression ──────────────────────────────────────────────

#pragma warning disable B58_001
    [Fact]
    public void DecodePlain_ObsoleteByteArray_StillReturnsCorrectBytes()
        => Assert.Equal("a"u8.ToArray(), Base58Encoding.DecodePlain("2g".AsSpan()));

    [Fact]
    public void TryDecodePlain_ObsoleteByteArray_ReturnsTrueAndCorrectBytes()
    {
        bool ok = Base58Encoding.TryDecodePlain("2g".AsSpan(), out byte[] result);
        Assert.True(ok);
        Assert.Equal("a"u8.ToArray(), result);
    }
#pragma warning restore B58_001
}
```

- [ ] **Step 2: Build and run the tests**

```bash
cd /Users/jtm/dev/Base58Check
dotnet test src/Tests/Tests.csproj --logger "console;verbosity=normal"
```

Expected: All tests pass. If any fail, the algorithm replacement in Task 3 has a bug — re-check the carry-propagation logic step by step against the Bitcoin test vectors.

- [ ] **Step 3: Commit**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Tests/EncodingTests.cs
git commit -m "test: migrate to xUnit v3; expand coverage for all span overloads and edge cases"
```

---

### Task 6: Write `Base58Value` tests (failing — TDD)

**Files:**
- Create: `src/Tests/Base58ValueTests.cs`

Write all tests before implementing `Base58Value`. The build will succeed because tests reference a type that does not yet exist — they will fail at runtime, not compile time... Actually since `Base58Value` doesn't exist yet, the project won't compile. Write the test file and verify the *compile* error; implementation in Task 7 makes them pass.

- [ ] **Step 1: Create `src/Tests/Base58ValueTests.cs`**

```csharp
using Base58Check;
using System.Text;
using Xunit;

namespace Tests;

public class Base58ValueTests
{
    private static readonly byte[] SampleBytes = "simply a long string"u8.ToArray();
    private const string SampleEncoded = "2cFupjhnEsSn59qHXstmK2ffpLv2";

    private static readonly byte[] AddressBytes = [0x00,0x01,0x09,0x66,0x77,0x60,0x06,0x95,0x3D,0x55,0x67,0x43,0x9E,0x5E,0x39,0xF8,0x6A,0x0D,0x27,0x3B,0xEE];
    private const string AddressText = "16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM";

    // ── Factory: Encode ───────────────────────────────────────────────────────────

    [Fact]
    public void Encode_ToString_MatchesEncodePlain()
        => Assert.Equal(Base58Encoding.EncodePlain(SampleBytes), Base58Value.Encode(SampleBytes).ToString());

    [Fact]
    public void Encode_Length_MatchesToStringLength()
    {
        var v = Base58Value.Encode(SampleBytes);
        Assert.Equal(v.ToString().Length, v.Length);
    }

    [Fact]
    public void Encode_EmptyBytes_ReturnsEmptyValue()
    {
        var v = Base58Value.Encode([]);
        Assert.Equal(string.Empty, v.ToString());
        Assert.Equal(0, v.Length);
    }

    // ── Factory: EncodeWithChecksum ────────────────────────────────────────────

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
        Assert.Equal(SampleEncoded, Encoding.UTF8.GetString(dest));
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
```

- [ ] **Step 2: Verify the test project fails to compile (expected)**

```bash
cd /Users/jtm/dev/Base58Check
dotnet build src/Tests/Tests.csproj 2>&1 | head -20
```

Expected: Compile error — `The type or namespace name 'Base58Value' could not be found`. This confirms the tests are wired to the right type.

- [ ] **Step 3: Commit the failing tests**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Tests/Base58ValueTests.cs
git commit -m "test: add Base58Value tests (failing — TDD)"
```

---

### Task 7: Implement `Base58Value`

**Files:**
- Create: `src/Base58Check/Base58Value.cs`

- [ ] **Step 1: Create `src/Base58Check/Base58Value.cs`**

```csharp
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
            int maxBytes = Base58Encoding.MaxBytes(encoded.Length);
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
```

- [ ] **Step 2: Build the library**

```bash
cd /Users/jtm/dev/Base58Check
dotnet build src/Base58Check/Base58Check.csproj
```

Expected: Build succeeds.

- [ ] **Step 3: Run all tests**

```bash
cd /Users/jtm/dev/Base58Check
dotnet test src/Tests/Tests.csproj --logger "console;verbosity=normal"
```

Expected: All tests pass. If any `Base58ValueTests` fail, re-check the implementation — most likely causes are the `Parse`/`TryParse` delegation or the `HasValidChecksum` buffer sizing.

- [ ] **Step 4: Commit**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Base58Check/Base58Value.cs
git commit -m "feat: add Base58Value with ISpanFormattable and IUtf8SpanFormattable"
```

---

### Task 8: Add BenchmarkDotNet project

**Files:**
- Create: `src/Benchmarks/Benchmarks.csproj`
- Create: `src/Benchmarks/Base58Benchmarks.cs`

- [ ] **Step 1: Create `src/Benchmarks/Benchmarks.csproj`**

```xml
<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <OutputType>Exe</OutputType>
    <TargetFramework>net10.0</TargetFramework>
    <LangVersion>latest</LangVersion>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
    <IsPublishable>false</IsPublishable>
    <AllowUnsafeBlocks>true</AllowUnsafeBlocks>
  </PropertyGroup>
  <ItemGroup>
    <ProjectReference Include="..\Base58Check\Base58Check.csproj" />
  </ItemGroup>
</Project>
```

- [ ] **Step 2: Add BenchmarkDotNet package**

```bash
cd /Users/jtm/dev/Base58Check
dotnet add src/Benchmarks/Benchmarks.csproj package BenchmarkDotNet
```

- [ ] **Step 3: Create `src/Benchmarks/Base58Benchmarks.cs`**

```csharp
using Base58Check;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Running;

BenchmarkSwitcher.FromAssembly(typeof(Base58Benchmarks).Assembly).Run(args);

[MemoryDiagnoser]
public class Base58Benchmarks
{
    private static readonly byte[] Input16  = new byte[16];
    private static readonly byte[] Input25  = new byte[25];
    private static readonly byte[] Input100 = new byte[100];

    private static readonly string Encoded16;
    private static readonly string Encoded25;
    private static readonly string Encoded100;
    private static readonly string EncodedChecksum16;
    private static readonly string EncodedChecksum25;
    private static readonly string EncodedChecksum100;
    private static readonly Guid   SampleGuid = Guid.NewGuid();

    // Reusable destination buffers (benchmarks must not allocate for output)
    private static readonly byte[] ByteDest = new byte[256];
    private static readonly char[] CharDest = new char[256];

    static Base58Benchmarks()
    {
        new Random(42).NextBytes(Input16);
        new Random(42).NextBytes(Input25);
        new Random(42).NextBytes(Input100);

        Encoded16          = Base58Encoding.EncodePlain(Input16);
        Encoded25          = Base58Encoding.EncodePlain(Input25);
        Encoded100         = Base58Encoding.EncodePlain(Input100);
        EncodedChecksum16  = Base58Encoding.EncodeWithChecksum(Input16);
        EncodedChecksum25  = Base58Encoding.EncodeWithChecksum(Input25);
        EncodedChecksum100 = Base58Encoding.EncodeWithChecksum(Input100);
    }

    // ── EncodePlain ───────────────────────────────────────────────────────────────

    [Benchmark] public string EncodePlain_16()  => Base58Encoding.EncodePlain(Input16);
    [Benchmark] public string EncodePlain_25()  => Base58Encoding.EncodePlain(Input25);
    [Benchmark] public string EncodePlain_100() => Base58Encoding.EncodePlain(Input100);

    // ── DecodePlain ───────────────────────────────────────────────────────────────

    [Benchmark] public int DecodePlain_16()  => Base58Encoding.DecodePlain(Encoded16.AsSpan(),  ByteDest);
    [Benchmark] public int DecodePlain_25()  => Base58Encoding.DecodePlain(Encoded25.AsSpan(),  ByteDest);
    [Benchmark] public int DecodePlain_100() => Base58Encoding.DecodePlain(Encoded100.AsSpan(), ByteDest);

    // ── EncodeWithChecksum ────────────────────────────────────────────────────────

    [Benchmark] public string EncodeWithChecksum_16()  => Base58Encoding.EncodeWithChecksum(Input16);
    [Benchmark] public string EncodeWithChecksum_25()  => Base58Encoding.EncodeWithChecksum(Input25);
    [Benchmark] public string EncodeWithChecksum_100() => Base58Encoding.EncodeWithChecksum(Input100);

    // ── DecodeWithChecksum ────────────────────────────────────────────────────────

    [Benchmark] public int DecodeWithChecksum_16()  => Base58Encoding.DecodeWithChecksum(EncodedChecksum16.AsSpan(),  ByteDest);
    [Benchmark] public int DecodeWithChecksum_25()  => Base58Encoding.DecodeWithChecksum(EncodedChecksum25.AsSpan(),  ByteDest);
    [Benchmark] public int DecodeWithChecksum_100() => Base58Encoding.DecodeWithChecksum(EncodedChecksum100.AsSpan(), ByteDest);

    // ── Guid ──────────────────────────────────────────────────────────────────────

    [Benchmark] public string EncodeGuid_String()   => Base58Encoding.EncodeGuid(SampleGuid);
    [Benchmark] public int    EncodeGuid_CharSpan() => Base58Encoding.EncodeGuid(SampleGuid, CharDest);
    [Benchmark] public Guid   DecodeGuid()          => Base58Encoding.DecodeGuid(Base58Encoding.EncodeGuid(SampleGuid).AsSpan());

    // ── Base58Value ───────────────────────────────────────────────────────────────

    [Benchmark] public Base58Value Base58Value_Encode_16() => Base58Value.Encode(Input16);
    [Benchmark] public Base58Value Base58Value_Encode_25() => Base58Value.Encode(Input25);

    [Benchmark]
    public int Base58Value_TryFormat_Utf8_16()
    {
        Base58Value.Encode(Input16).TryFormat(ByteDest, out int n, default, null);
        return n;
    }

    [Benchmark]
    public int Base58Value_TryFormat_Utf8_25()
    {
        Base58Value.Encode(Input25).TryFormat(ByteDest, out int n, default, null);
        return n;
    }
}
```

- [ ] **Step 4: Add the Benchmarks project to the solution**

```bash
cd /Users/jtm/dev/Base58Check
dotnet sln Base58Check.sln add src/Benchmarks/Benchmarks.csproj
```

- [ ] **Step 5: Build the benchmarks project**

```bash
cd /Users/jtm/dev/Base58Check
dotnet build src/Benchmarks/Benchmarks.csproj -c Release
```

Expected: Build succeeds.

- [ ] **Step 6: Run a quick smoke test (dry run, not a full benchmark)**

```bash
cd /Users/jtm/dev/Base58Check
dotnet run --project src/Benchmarks/Benchmarks.csproj -c Release -- --list flat
```

Expected: Lists all benchmark method names without running them. If this succeeds, the project is wired correctly.

- [ ] **Step 7: Run all tests one final time to confirm nothing regressed**

```bash
cd /Users/jtm/dev/Base58Check
dotnet test src/Tests/Tests.csproj --logger "console;verbosity=normal"
```

Expected: All tests pass.

- [ ] **Step 8: Commit**

```bash
cd /Users/jtm/dev/Base58Check
git add src/Benchmarks/ Base58Check.sln
git commit -m "chore: add BenchmarkDotNet project for Base58 encode/decode/Base58Value benchmarks"
```
