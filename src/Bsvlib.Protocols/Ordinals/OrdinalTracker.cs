namespace Bsvlib.Protocols;

/// <summary>
/// 按序数理论把输入里的聪依次填进输出。第 n 聪进入第 n 个输出位置，多出来的是手续费。
/// </summary>
public static class OrdinalTracker
{
    public static IReadOnlyList<SatRange> FromValues(IReadOnlyList<long> values)
    {
        ArgumentNullException.ThrowIfNull(values);
        var ranges = new List<SatRange>(values.Count);
        long cursor = 0;
        foreach (long value in values)
        {
            if (value < 0)
                throw new ArgumentOutOfRangeException(nameof(values));
            if (value == 0)
                continue;
            ranges.Add(SatRange.FromLength(cursor, value));
            cursor += value;
        }

        return ranges;
    }

    public static OrdinalAssignment Assign(IReadOnlyList<SatRange> inputs, IReadOnlyList<long> outputValues)
    {
        if (!TryAssign(inputs, outputValues, out OrdinalAssignment? assignment))
            throw new InvalidOperationException("Outputs ask for more satoshis than the inputs carry.");
        return assignment!;
    }

    public static bool TryAssign(IReadOnlyList<SatRange> inputs, IReadOnlyList<long> outputValues, out OrdinalAssignment? assignment)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(outputValues);
        assignment = null;
        int rangeIndex = 0;
        long offset = 0;
        var outputs = new List<SatRange>[outputValues.Count];
        for (int output = 0; output < outputValues.Count; output++)
        {
            long need = outputValues[output];
            if (need < 0)
                throw new ArgumentOutOfRangeException(nameof(outputValues));
            var pieces = new List<SatRange>();
            while (need > 0)
            {
                if (rangeIndex >= inputs.Count)
                    return false;
                SatRange range = inputs[rangeIndex];
                long available = range.Length - offset;
                long take = Math.Min(need, available);
                pieces.Add(SatRange.FromLength(range.Start + offset, take));
                need -= take;
                offset += take;
                if (offset == range.Length)
                {
                    rangeIndex++;
                    offset = 0;
                }
            }

            outputs[output] = pieces;
        }

        var fee = new List<SatRange>();
        if (rangeIndex < inputs.Count)
        {
            SatRange first = inputs[rangeIndex];
            if (offset > 0)
                fee.Add(new SatRange(first.Start + offset, first.End));
            for (int i = rangeIndex + (offset > 0 ? 1 : 0); i < inputs.Count; i++)
                fee.Add(inputs[i]);
        }

        assignment = new OrdinalAssignment(outputs, fee);
        return true;
    }

    public static bool TryLocate(OrdinalAssignment assignment, long sat, out int outputIndex)
    {
        ArgumentNullException.ThrowIfNull(assignment);
        for (int i = 0; i < assignment.Outputs.Count; i++)
        {
            foreach (SatRange range in assignment.Outputs[i])
            {
                if (range.Contains(sat))
                {
                    outputIndex = i;
                    return true;
                }
            }
        }

        outputIndex = -1;
        return false;
    }
}

public sealed class OrdinalAssignment
{
    public OrdinalAssignment(IReadOnlyList<IReadOnlyList<SatRange>> outputs, IReadOnlyList<SatRange> fee)
    {
        Outputs = outputs;
        Fee = fee;
    }

    public IReadOnlyList<IReadOnlyList<SatRange>> Outputs { get; }

    public IReadOnlyList<SatRange> Fee { get; }
}
