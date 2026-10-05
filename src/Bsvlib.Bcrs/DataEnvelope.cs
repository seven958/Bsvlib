using System.Buffers.Binary;
using Bsvlib.Core;

namespace Bsvlib.Bcrs;

/// <summary>OP_FALSE OP_RETURN 后面的一串 pushdata。第一段是协议标识。</summary>
public sealed class DataEnvelope
{
    private const byte OpReturn = 0x6A;
    private const byte OpPushData1 = 0x4C;
    private const byte OpPushData2 = 0x4D;
    private const byte OpPushData4 = 0x4E;

    private readonly byte[][] _fields;

    public DataEnvelope(ReadOnlySpan<byte> protocol, IReadOnlyList<byte[]> fields)
    {
        if (protocol.IsEmpty)
            throw new ArgumentException("Protocol identifier must not be empty.", nameof(protocol));
        ArgumentNullException.ThrowIfNull(fields);
        _fields = new byte[fields.Count + 1][];
        _fields[0] = protocol.ToArray();
        for (int i = 0; i < fields.Count; i++)
            _fields[i + 1] = fields[i]?.ToArray() ?? throw new ArgumentException("A field is null.", nameof(fields));
    }

    public ReadOnlyMemory<byte> Protocol => _fields[0];

    public IReadOnlyList<byte[]> Fields => _fields;

    public Script ToScript()
    {
        int size = 2;
        foreach (byte[] field in _fields)
            size += PushLength(field.Length) + field.Length;
        var script = new byte[size];
        script[1] = OpReturn;
        int offset = 2;
        foreach (byte[] field in _fields)
            offset += WritePush(script.AsSpan(offset), field);
        return new Script(script);
    }

    public static bool TryParse(Script script, out DataEnvelope? envelope)
    {
        envelope = null;
        ReadOnlySpan<byte> bytes = script.Bytes.Span;
        if (bytes.Length < 2 || bytes[0] != 0 || bytes[1] != OpReturn)
            return false;

        var fields = new List<byte[]>();
        int offset = 2;
        while (offset < bytes.Length)
        {
            if (!TryReadPush(bytes, ref offset, out byte[]? field))
                return false;
            fields.Add(field!);
        }

        if (fields.Count == 0)
            return false;
        envelope = new DataEnvelope(fields[0], fields.Skip(1).ToList());
        return true;
    }

    private static int PushLength(int dataLength)
    {
        if (dataLength <= 75)
            return 1;
        if (dataLength <= byte.MaxValue)
            return 2;
        if (dataLength <= ushort.MaxValue)
            return 3;
        return 5;
    }

    private static int WritePush(Span<byte> destination, ReadOnlySpan<byte> data)
    {
        if (data.Length <= 75)
        {
            destination[0] = (byte)data.Length;
            data.CopyTo(destination[1..]);
            return 1 + data.Length;
        }

        if (data.Length <= byte.MaxValue)
        {
            destination[0] = OpPushData1;
            destination[1] = (byte)data.Length;
            data.CopyTo(destination[2..]);
            return 2 + data.Length;
        }

        if (data.Length <= ushort.MaxValue)
        {
            destination[0] = OpPushData2;
            BinaryPrimitives.WriteUInt16LittleEndian(destination[1..], (ushort)data.Length);
            data.CopyTo(destination[3..]);
            return 3 + data.Length;
        }

        destination[0] = OpPushData4;
        BinaryPrimitives.WriteUInt32LittleEndian(destination[1..], (uint)data.Length);
        data.CopyTo(destination[5..]);
        return 5 + data.Length;
    }

    private static bool TryReadPush(ReadOnlySpan<byte> script, ref int offset, out byte[]? data)
    {
        data = null;
        if (offset >= script.Length)
            return false;
        int opcode = script[offset++];
        int length;
        if (opcode is > 0 and < OpPushData1)
        {
            length = opcode;
        }
        else if (opcode == OpPushData1)
        {
            if (offset >= script.Length)
                return false;
            length = script[offset++];
        }
        else if (opcode == OpPushData2)
        {
            if (script.Length - offset < 2)
                return false;
            length = BinaryPrimitives.ReadUInt16LittleEndian(script[offset..]);
            offset += 2;
        }
        else if (opcode == OpPushData4)
        {
            if (script.Length - offset < 4)
                return false;
            uint wide = BinaryPrimitives.ReadUInt32LittleEndian(script[offset..]);
            if (wide > int.MaxValue)
                return false;
            length = (int)wide;
            offset += 4;
        }
        else
        {
            return false;
        }

        if (script.Length - offset < length)
            return false;
        data = script.Slice(offset, length).ToArray();
        offset += length;
        return true;
    }
}
