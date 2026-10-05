using System.Buffers.Binary;

namespace Bsvlib.Core;

internal ref struct SpanReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _offset;

    public SpanReader(ReadOnlySpan<byte> data) => _data = data;

    public int Consumed => _offset;

    public int Remaining => _data.Length - _offset;

    public bool TryReadBytes(int count, out ReadOnlySpan<byte> bytes)
    {
        bytes = default;
        if (count < 0 || Remaining < count)
            return false;
        bytes = _data.Slice(_offset, count);
        _offset += count;
        return true;
    }

    public bool TryReadInt32(out int value)
    {
        value = 0;
        if (!TryReadBytes(4, out ReadOnlySpan<byte> bytes))
            return false;
        value = BinaryPrimitives.ReadInt32LittleEndian(bytes);
        return true;
    }

    public bool TryReadUInt32(out uint value)
    {
        value = 0;
        if (!TryReadBytes(4, out ReadOnlySpan<byte> bytes))
            return false;
        value = BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        return true;
    }

    public bool TryReadInt64(out long value)
    {
        value = 0;
        if (!TryReadBytes(8, out ReadOnlySpan<byte> bytes))
            return false;
        value = BinaryPrimitives.ReadInt64LittleEndian(bytes);
        return true;
    }

    public bool TryReadVarInt(out ulong value)
    {
        if (!VarInt.TryRead(_data[_offset..], out value, out int consumed))
            return false;
        _offset += consumed;
        return true;
    }
}
