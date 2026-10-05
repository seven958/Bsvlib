using System.Numerics;

namespace Bsvlib.Core;

/// <summary>脚本数字：小端，最高字节的最高位是符号位。</summary>
public static class ScriptNum
{
    public const int MaxLength = 750_000;

    public static bool IsMinimallyEncoded(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return true;
        if ((data[^1] & 0x7F) != 0)
            return true;
        return data.Length >= 2 && (data[^2] & 0x80) != 0;
    }

    public static bool TryDecode(ReadOnlySpan<byte> data, out BigInteger value, bool requireMinimal = true)
    {
        value = BigInteger.Zero;
        if (data.Length > MaxLength || (requireMinimal && !IsMinimallyEncoded(data)))
            return false;
        if (data.IsEmpty)
            return true;

        bool negative = (data[^1] & 0x80) != 0;
        var magnitude = data.ToArray();
        magnitude[^1] &= 0x7F;
        value = new BigInteger(magnitude, isUnsigned: true, isBigEndian: false);
        if (negative)
            value = -value;
        return true;
    }

    public static byte[] Encode(BigInteger value)
    {
        if (value.IsZero)
            return [];

        bool negative = value.Sign < 0;
        byte[] magnitude = BigInteger.Abs(value).ToByteArray(isUnsigned: true, isBigEndian: false);
        if ((magnitude[^1] & 0x80) != 0)
            Array.Resize(ref magnitude, magnitude.Length + 1);
        if (negative)
            magnitude[^1] |= 0x80;
        return magnitude;
    }

    public static bool TryNum2Bin(BigInteger value, int size, out byte[] encoded)
    {
        encoded = [];
        if (size < 0 || size > MaxLength)
            return false;
        byte[] minimal = Encode(value);
        if (minimal.Length > size)
            return false;
        if (minimal.Length == size)
        {
            encoded = minimal;
            return true;
        }

        encoded = new byte[size];
        minimal.CopyTo(encoded, 0);
        if (value.Sign < 0 && minimal.Length > 0)
        {
            encoded[minimal.Length - 1] &= 0x7F;
            encoded[^1] |= 0x80;
        }

        return true;
    }
}
