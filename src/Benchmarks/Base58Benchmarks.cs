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
