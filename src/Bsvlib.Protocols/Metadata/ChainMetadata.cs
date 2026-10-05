using System.Text;
using Bsvlib.Bcrs;
using Bsvlib.Core;

namespace Bsvlib.Protocols;

/// <summary>Magic Attribute Protocol。前缀后面是命令和成对的键值，例如 SET app demo。</summary>
public sealed class MapRecord
{
    public const string Prefix = "1PuQa7K62MiKCtssSLKy1kh56WWU7MtUR5";

    public MapRecord(string command, IReadOnlyList<KeyValuePair<string, string>> attributes)
    {
        if (string.IsNullOrEmpty(command))
            throw new ArgumentException("Command is required.", nameof(command));
        ArgumentNullException.ThrowIfNull(attributes);
        Command = command;
        Attributes = attributes;
    }

    public string Command { get; }

    public IReadOnlyList<KeyValuePair<string, string>> Attributes { get; }

    public DataEnvelope ToEnvelope() => new(PrefixBytes(), Fields());

    public static bool TryParse(Script script, out MapRecord? record) =>
        TryParse(script, out record, Prefix);

    internal static bool TryParse(Script script, out MapRecord? record, string prefix)
    {
        record = null;
        if (!OpReturnFields.TryRead(script, out IReadOnlyList<byte[]>? fields) || fields!.Count < 2)
            return false;
        if (!Encoding.UTF8.GetString(fields[0]).Equals(prefix, StringComparison.Ordinal))
            return false;
        string command = Encoding.UTF8.GetString(fields[1]);
        if ((fields.Count - 2) % 2 != 0)
            return false;
        var attributes = new List<KeyValuePair<string, string>>((fields.Count - 2) / 2);
        for (int i = 2; i < fields.Count; i += 2)
            attributes.Add(new KeyValuePair<string, string>(Encoding.UTF8.GetString(fields[i]), Encoding.UTF8.GetString(fields[i + 1])));
        record = new MapRecord(command, attributes);
        return true;
    }

    private static byte[] PrefixBytes() => Encoding.UTF8.GetBytes(Prefix);

    private byte[][] Fields()
    {
        var fields = new byte[1 + Attributes.Count * 2][];
        fields[0] = Encoding.UTF8.GetBytes(Command);
        for (int i = 0; i < Attributes.Count; i++)
        {
            fields[1 + i * 2] = Encoding.UTF8.GetBytes(Attributes[i].Key);
            fields[2 + i * 2] = Encoding.UTF8.GetBytes(Attributes[i].Value);
        }

        return fields;
    }
}

/// <summary>B://。前缀后面依次是数据、媒体类型、编码和文件名。</summary>
public sealed class BinaryContent
{
    public const string Prefix = "19HxigV4QyBv3tHpQVcUEQyq1pzZVdoAut";

    public BinaryContent(ReadOnlySpan<byte> data, string mediaType, string encoding, string fileName)
    {
        ArgumentNullException.ThrowIfNull(mediaType);
        ArgumentNullException.ThrowIfNull(encoding);
        ArgumentNullException.ThrowIfNull(fileName);
        Data = data.ToArray();
        MediaType = mediaType;
        EncodingName = encoding;
        FileName = fileName;
    }

    public ReadOnlyMemory<byte> Data { get; }

    public string MediaType { get; }

    public string EncodingName { get; }

    public string FileName { get; }

    public DataEnvelope ToEnvelope() => new(Encoding.UTF8.GetBytes(Prefix),
    [
        Data.ToArray(),
        Encoding.UTF8.GetBytes(MediaType),
        Encoding.UTF8.GetBytes(EncodingName),
        Encoding.UTF8.GetBytes(FileName),
    ]);

    public static bool TryParse(Script script, out BinaryContent? content)
    {
        content = null;
        if (!OpReturnFields.TryRead(script, out IReadOnlyList<byte[]>? fields) || fields!.Count != 5)
            return false;
        if (Encoding.UTF8.GetString(fields[0]) != Prefix)
            return false;
        content = new BinaryContent(fields[1], Encoding.UTF8.GetString(fields[2]), Encoding.UTF8.GetString(fields[3]), Encoding.UTF8.GetString(fields[4]));
        return true;
    }
}

/// <summary>Author Identity Protocol。前缀后面是算法、地址、签名和被签名字段的下标。</summary>
public sealed class AuthorIdentity
{
    public const string Prefix = "15PciHG22SNLQJXMoSUaWVi7WSqc7hCfva";

    public AuthorIdentity(string algorithm, string address, string signature, string indices)
    {
        ArgumentNullException.ThrowIfNull(algorithm);
        ArgumentNullException.ThrowIfNull(address);
        ArgumentNullException.ThrowIfNull(signature);
        ArgumentNullException.ThrowIfNull(indices);
        Algorithm = algorithm;
        Address = address;
        Signature = signature;
        Indices = indices;
    }

    public string Algorithm { get; }

    public string Address { get; }

    public string Signature { get; }

    public string Indices { get; }

    public DataEnvelope ToEnvelope() => new(Encoding.UTF8.GetBytes(Prefix),
    [
        Encoding.UTF8.GetBytes(Algorithm),
        Encoding.UTF8.GetBytes(Address),
        Encoding.UTF8.GetBytes(Signature),
        Encoding.UTF8.GetBytes(Indices),
    ]);

    public static bool TryParse(Script script, out AuthorIdentity? identity)
    {
        identity = null;
        if (!OpReturnFields.TryRead(script, out IReadOnlyList<byte[]>? fields) || fields!.Count != 5)
            return false;
        if (Encoding.UTF8.GetString(fields[0]) != Prefix)
            return false;
        identity = new AuthorIdentity(
            Encoding.UTF8.GetString(fields[1]),
            Encoding.UTF8.GetString(fields[2]),
            Encoding.UTF8.GetString(fields[3]),
            Encoding.UTF8.GetString(fields[4]));
        return true;
    }
}

internal static class OpReturnFields
{
    private const byte OpReturn = 0x6A;
    private const byte OpPushData1 = 0x4C;
    private const byte OpPushData2 = 0x4D;
    private const byte OpPushData4 = 0x4E;

    public static bool TryRead(Script script, out IReadOnlyList<byte[]>? fields)
    {
        fields = null;
        ArgumentNullException.ThrowIfNull(script);
        ReadOnlySpan<byte> bytes = script.Bytes.Span;
        int offset = 0;
        while (offset < bytes.Length)
        {
            if (bytes[offset] == OpReturn)
            {
                offset++;
                var found = new List<byte[]>();
                while (offset < bytes.Length && TryReadData(bytes, ref offset, out byte[]? data))
                    found.Add(data!);
                if (offset != bytes.Length)
                    return false;
                fields = found;
                return true;
            }

            if (!TrySkip(bytes, ref offset))
                return false;
        }

        return false;
    }

    private static bool TrySkip(ReadOnlySpan<byte> script, ref int offset)
    {
        if (script[offset] is > 0 and < OpPushData1 or OpPushData1 or OpPushData2 or OpPushData4)
            return TryReadData(script, ref offset, out _);
        offset++;
        return true;
    }

    private static bool TryReadData(ReadOnlySpan<byte> script, ref int offset, out byte[]? data)
    {
        data = null;
        if (offset >= script.Length)
            return false;
        byte opcode = script[offset];
        int length;
        if (opcode is > 0 and < OpPushData1)
        {
            length = opcode;
            offset++;
        }
        else if (opcode == OpPushData1)
        {
            if (script.Length - offset < 2)
                return false;
            length = script[offset + 1];
            offset += 2;
        }
        else if (opcode == OpPushData2)
        {
            if (script.Length - offset < 3)
                return false;
            length = System.Buffers.Binary.BinaryPrimitives.ReadUInt16LittleEndian(script[(offset + 1)..]);
            offset += 3;
        }
        else if (opcode == OpPushData4)
        {
            if (script.Length - offset < 5)
                return false;
            uint wide = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(script[(offset + 1)..]);
            if (wide > int.MaxValue)
                return false;
            length = (int)wide;
            offset += 5;
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
