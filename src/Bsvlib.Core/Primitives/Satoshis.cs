namespace Bsvlib.Core;

/// <summary>聪。非负，且不超过 2100 万 BSV。</summary>
public readonly record struct Satoshis
{
    public const long MaxValue = 21_000_000L * 100_000_000L;

    public long Value { get; }

    public Satoshis(long value)
    {
        if (value < 0 || value > MaxValue)
            throw new ArgumentOutOfRangeException(nameof(value));
        Value = value;
    }

    public static Satoshis Zero { get; } = new(0);

    public static bool TryCreate(long value, out Satoshis amount)
    {
        if (value < 0 || value > MaxValue)
        {
            amount = default;
            return false;
        }

        amount = new Satoshis(value);
        return true;
    }

    public Satoshis Add(Satoshis other)
    {
        long sum = checked(Value + other.Value);
        if (sum > MaxValue)
            throw new OverflowException();
        return new Satoshis(sum);
    }

    public Satoshis Subtract(Satoshis other)
    {
        if (other.Value > Value)
            throw new OverflowException();
        return new Satoshis(Value - other.Value);
    }

    public override string ToString() => Value.ToString(System.Globalization.CultureInfo.InvariantCulture);
}
