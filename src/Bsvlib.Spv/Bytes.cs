namespace Bsvlib.Spv;

internal ref struct ByteReader
{
    private readonly ReadOnlySpan<byte> _data;
    private int _offset;

    public ByteReader(ReadOnlySpan<byte> data) => _data = data;

    public int Consumed => _offset;

    public bool TryReadByte(out byte value)
    {
        value = 0;
        if (_offset >= _data.Length)
            return false;
        value = _data[_offset++];
        return true;
    }

    public bool TryReadBytes(int count, out ReadOnlySpan<byte> bytes)
    {
        bytes = default;
        if (count < 0 || _data.Length - _offset < count)
            return false;
        bytes = _data.Slice(_offset, count);
        _offset += count;
        return true;
    }

    public bool TryReadUInt32(out uint value)
    {
        value = 0;
        if (!TryReadBytes(4, out ReadOnlySpan<byte> bytes))
            return false;
        value = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(bytes);
        return true;
    }

    public bool TryReadVarInt(out ulong value)
    {
        if (!Bsvlib.Core.VarInt.TryRead(_data[_offset..], out value, out int consumed))
            return false;
        _offset += consumed;
        return true;
    }
}

internal sealed class ByteWriter
{
    private byte[] _buffer = new byte[256];
    private int _length;

    public void WriteByte(byte value)
    {
        Ensure(1);
        _buffer[_length++] = value;
    }

    public void Write(ReadOnlySpan<byte> data)
    {
        Ensure(data.Length);
        data.CopyTo(_buffer.AsSpan(_length));
        _length += data.Length;
    }

    public void WriteUInt32(uint value)
    {
        Span<byte> bytes = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(bytes, value);
        Write(bytes);
    }

    public void WriteVarInt(ulong value)
    {
        Span<byte> bytes = stackalloc byte[9];
        int written = Bsvlib.Core.VarInt.Write(bytes, value);
        Write(bytes[..written]);
    }

    public byte[] ToArray() => _buffer.AsSpan(0, _length).ToArray();

    private void Ensure(int extra)
    {
        if (_length + extra <= _buffer.Length)
            return;
        Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, _length + extra));
    }
}
