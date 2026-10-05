using System.Globalization;
using System.Numerics;

namespace Bsvlib.Core;

/// <summary>压缩难度位与工作量。比较规则与 bitcoin-sv 的 arith_uint256 一致。</summary>
public static class ProofOfWork
{
    public static BigInteger DecodeCompact(uint bits, out bool negative, out bool overflow)
    {
        int size = (int)(bits >> 24);
        uint word = bits & 0x007f_ffff;
        BigInteger target = size <= 3
            ? word >> (8 * (3 - size))
            : (BigInteger)word << (8 * (size - 3));
        negative = word != 0 && (bits & 0x0080_0000) != 0;
        overflow = word != 0 && (size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32));
        return target;
    }

    public static uint EncodeCompact(BigInteger value)
    {
        if (value.Sign < 0)
            throw new ArgumentOutOfRangeException(nameof(value));
        int bitLength = value.IsZero ? 0 : (int)value.GetBitLength();
        int size = (bitLength + 7) / 8;
        uint compact = size <= 3
            ? (uint)value << (8 * (3 - size))
            : (uint)((value >> (8 * (size - 3))) & uint.MaxValue);
        if ((compact & 0x0080_0000) != 0)
        {
            compact >>= 8;
            size++;
        }

        return compact | (uint)size << 24;
    }

    public static bool Check(TxId hash, uint bits, BigInteger powLimit)
    {
        BigInteger target = DecodeCompact(bits, out bool negative, out bool overflow);
        if (negative || target.IsZero || overflow || target > powLimit)
            return false;
        return FromLittleEndian(hash.ToWire()) <= target;
    }

    public static BigInteger Work(uint bits)
    {
        BigInteger target = DecodeCompact(bits, out bool negative, out bool overflow);
        if (negative || overflow || target.IsZero)
            return BigInteger.Zero;
        return (BigInteger.One << 256) / (target + BigInteger.One);
    }

    public static BigInteger ParseUnsigned(string hex)
    {
        if (!BigInteger.TryParse(hex, NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out BigInteger value) || value.Sign < 0)
            throw new FormatException("Value must be an unsigned hexadecimal integer.");
        return value;
    }

    private static BigInteger FromLittleEndian(ReadOnlySpan<byte> bytes)
    {
        Span<byte> little = stackalloc byte[bytes.Length + 1];
        bytes.CopyTo(little);
        return new BigInteger(little);
    }
}
