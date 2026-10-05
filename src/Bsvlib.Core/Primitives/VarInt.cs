namespace Bsvlib.Core;

/// <summary>比特币 CompactSize / VarInt。写入使用最短形式，读取接受非最短编码。</summary>
public static class VarInt
{
    public static int GetSize(ulong value) => value switch
    {
        < 0xFD => 1,
        <= ushort.MaxValue => 3,
        <= uint.MaxValue => 5,
        _ => 9,
    };

    public static int Write(Span<byte> destination, ulong value)
    {
        int size = GetSize(value);
        if (destination.Length < size)
            throw new ArgumentException($"Destination must be at least {size} bytes.", nameof(destination));

        if (value < 0xFD)
        {
            destination[0] = (byte)value;
        }
        else if (value <= ushort.MaxValue)
        {
            destination[0] = 0xFD;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt16LittleEndian(destination[1..], (ushort)value);
        }
        else if (value <= uint.MaxValue)
        {
            destination[0] = 0xFE;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination[1..], (uint)value);
        }
        else
        {
            destination[0] = 0xFF;
            System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(destination[1..], value);
        }

        return size;
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out ulong value, out int consumed)
    {
        value = 0;
        consumed = 0;
        if (data.IsEmpty)
            return false;

        byte prefix = data[0];
        if (prefix < 0xFD)
        {
            value = prefix;
            consumed = 1;
            return true;
        }

        if (prefix == 0xFD)
        {
            if (data.Length < 3)
                return false;
            value = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(data[1..]);
            consumed = 3;
            return true;
        }

        if (prefix == 0xFE)
        {
            if (data.Length < 5)
                return false;
            value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(data[1..]);
            consumed = 5;
            return true;
        }

        if (data.Length < 9)
            return false;
        value = System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(data[1..]);
        consumed = 9;
        return true;
    }
}
