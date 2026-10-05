namespace Bsvlib.Protocols;

/// <summary>半开区间 [Start, End)，表示一段连续的聪。</summary>
public readonly record struct SatRange
{
    public SatRange(long start, long end)
    {
        if (start < 0)
            throw new ArgumentOutOfRangeException(nameof(start));
        if (end <= start)
            throw new ArgumentOutOfRangeException(nameof(end));
        Start = start;
        End = end;
    }

    public long Start { get; }

    public long End { get; }

    public long Length => End - Start;

    public bool Contains(long sat) => sat >= Start && sat < End;

    public static SatRange FromLength(long start, long length)
    {
        if (length <= 0)
            throw new ArgumentOutOfRangeException(nameof(length));
        return new SatRange(start, checked(start + length));
    }
}
