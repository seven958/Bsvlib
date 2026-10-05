using System.Numerics;

namespace Bsvlib.Core;

/// <summary>
/// 下一区块的难度。daaHeight 之前沿用比特币的 2016 块调整和 EDA，之后使用 CW-144。
/// </summary>
public static class Difficulty
{
    private const int MedianSpan = 11;

    private const int CashWindow = 144;

    public static uint NextBits(IReadOnlyList<BlockHeader> headers, IReadOnlyList<BigInteger> chainWork, ChainParameters parameters, uint nextTime)
    {
        ArgumentNullException.ThrowIfNull(headers);
        ArgumentNullException.ThrowIfNull(chainWork);
        ArgumentNullException.ThrowIfNull(parameters);
        if (headers.Count == 0)
            return parameters.PowLimitCompact;
        if (headers.Count != chainWork.Count)
            throw new ArgumentException("Chain work must have one entry per header.", nameof(chainWork));

        BlockHeader previous = headers[^1];
        if (parameters.NoRetargeting)
            return previous.Bits;

        int previousHeight = headers.Count - 1;
        if (previousHeight >= parameters.DaaHeight)
            return CashWork(headers, chainWork, parameters, nextTime);
        return LegacyWork(headers, parameters, nextTime);
    }

    private static uint LegacyWork(IReadOnlyList<BlockHeader> headers, ChainParameters parameters, uint nextTime)
    {
        int previousHeight = headers.Count - 1;
        int nextHeight = previousHeight + 1;
        BlockHeader previous = headers[previousHeight];
        if (nextHeight % parameters.DifficultyAdjustmentInterval == 0)
        {
            int firstHeight = nextHeight - parameters.DifficultyAdjustmentInterval;
            return Retarget(previous.Bits, previous.Time, headers[firstHeight].Time, parameters);
        }

        uint limit = parameters.PowLimitCompact;
        if (parameters.AllowMinDifficultyBlocks)
        {
            if (nextTime > previous.Time + 2L * parameters.TargetSpacing)
                return limit;
            int height = previousHeight;
            while (height > 0 && height % parameters.DifficultyAdjustmentInterval != 0 && headers[height].Bits == limit)
                height--;
            return headers[height].Bits;
        }

        if (previous.Bits == limit)
            return limit;

        int ancestor = nextHeight - 7;
        if (ancestor < 0)
            return previous.Bits;
        long elapsed = MedianTime(headers, previousHeight) - MedianTime(headers, ancestor);
        if (elapsed < 12 * 3600)
            return previous.Bits;

        BigInteger eased = ProofOfWork.DecodeCompact(previous.Bits, out _, out _);
        eased += eased >> 2;
        if (eased > parameters.PowLimit)
            eased = parameters.PowLimit;
        return ProofOfWork.EncodeCompact(eased);
    }

    private static uint Retarget(uint bits, uint lastTime, uint firstTime, ChainParameters parameters)
    {
        long actual = (long)lastTime - firstTime;
        long span = parameters.TargetTimespan;
        if (actual < span / 4)
            actual = span / 4;
        if (actual > span * 4)
            actual = span * 4;

        BigInteger next = ProofOfWork.DecodeCompact(bits, out _, out _) * actual / span;
        if (next > parameters.PowLimit)
            next = parameters.PowLimit;
        return ProofOfWork.EncodeCompact(next);
    }

    private static uint CashWork(IReadOnlyList<BlockHeader> headers, IReadOnlyList<BigInteger> chainWork, ChainParameters parameters, uint nextTime)
    {
        int previousHeight = headers.Count - 1;
        BlockHeader previous = headers[previousHeight];
        if (parameters.AllowMinDifficultyBlocks && nextTime > previous.Time + 2L * parameters.TargetSpacing)
            return parameters.PowLimitCompact;
        if (previousHeight < parameters.DifficultyAdjustmentInterval || previousHeight < CashWindow + 2)
            throw new InvalidOperationException("Cash work requires a longer header chain.");

        int last = MedianOfThree(headers, previousHeight);
        int first = MedianOfThree(headers, previousHeight - CashWindow);
        BigInteger work = chainWork[last] - chainWork[first];
        work *= parameters.TargetSpacing;
        long actual = (long)headers[last].Time - headers[first].Time;
        if (actual > 288L * parameters.TargetSpacing)
            actual = 288L * parameters.TargetSpacing;
        else if (actual < 72L * parameters.TargetSpacing)
            actual = 72L * parameters.TargetSpacing;
        work /= actual;
        if (work.Sign <= 0)
            return parameters.PowLimitCompact;

        BigInteger target = ((BigInteger.One << 256) - work) / work;
        if (target > parameters.PowLimit)
            return parameters.PowLimitCompact;
        return ProofOfWork.EncodeCompact(target);
    }

    private static int MedianOfThree(IReadOnlyList<BlockHeader> headers, int height)
    {
        int[] index = [height - 2, height - 1, height];
        if (headers[index[0]].Time > headers[index[2]].Time)
            (index[0], index[2]) = (index[2], index[0]);
        if (headers[index[0]].Time > headers[index[1]].Time)
            (index[0], index[1]) = (index[1], index[0]);
        if (headers[index[1]].Time > headers[index[2]].Time)
            (index[1], index[2]) = (index[2], index[1]);
        return index[1];
    }

    private static long MedianTime(IReadOnlyList<BlockHeader> headers, int height)
    {
        Span<long> times = stackalloc long[MedianSpan];
        int count = 0;
        for (int i = 0; i < MedianSpan && height - i >= 0; i++)
            times[count++] = headers[height - i].Time;
        times[..count].Sort();
        return times[count / 2];
    }
}
