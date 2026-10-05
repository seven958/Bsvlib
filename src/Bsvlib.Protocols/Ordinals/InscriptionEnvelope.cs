using System.Text;
using Bsvlib.Core;

namespace Bsvlib.Protocols;

/// <summary>
/// ord 信封：OP_FALSE OP_IF "ord" 字段对 OP_0 正文 OP_ENDIF。
/// 锁定脚本可以放在信封前面或后面。只认脚本里的第一份信封。
/// </summary>
public sealed class InscriptionEnvelope
{
    private const byte OpFalse = 0x00;
    private const byte OpIf = 0x63;
    private const byte OpEndIf = 0x68;
    private const byte OpCodeSeparator = 0xAB;
    private const byte OpPushData1 = 0x4C;
    private const byte OpPushData2 = 0x4D;
    private const byte OpPushData4 = 0x4E;

    private static readonly byte[] Protocol = "ord"u8.ToArray();

    private InscriptionEnvelope(Inscription inscription, Script lockingScript)
    {
        Inscription = inscription;
        LockingScript = lockingScript;
    }

    public Inscription Inscription { get; }

    public Script LockingScript { get; }

    public static Script Create(Inscription inscription, Script? lockingScript = null, bool lockingScriptFirst = true)
    {
        ArgumentNullException.ThrowIfNull(inscription);
        byte[] envelope = WriteEnvelope(inscription);
        if (lockingScript is null || lockingScript.Bytes.Length == 0)
            return new Script(envelope);
        var script = new byte[lockingScript.Bytes.Length + envelope.Length];
        if (lockingScriptFirst)
        {
            lockingScript.Bytes.Span.CopyTo(script);
            envelope.CopyTo(script.AsSpan(lockingScript.Bytes.Length));
        }
        else
        {
            envelope.CopyTo(script);
            lockingScript.Bytes.Span.CopyTo(script.AsSpan(envelope.Length));
        }

        return new Script(script);
    }

    public static bool TryParse(Script script, out InscriptionEnvelope? envelope)
    {
        envelope = null;
        ArgumentNullException.ThrowIfNull(script);
        ReadOnlySpan<byte> bytes = script.Bytes.Span;
        int offset = 0;
        while (offset < bytes.Length)
        {
            if (bytes[offset] == OpFalse && offset + 1 < bytes.Length && bytes[offset + 1] == OpIf && TryReadEnvelope(bytes, offset, out int end, out Inscription? inscription))
            {
                envelope = new InscriptionEnvelope(inscription!, LockingScriptAround(bytes, offset, end));
                return true;
            }

            if (!TrySkip(bytes, ref offset))
                return false;
        }

        return false;
    }

    private static byte[] WriteEnvelope(Inscription inscription)
    {
        var script = new List<byte> { OpFalse, OpIf };
        WriteData(script, Protocol);
        if (inscription.ContentType is not null)
        {
            WriteTag(script, Inscription.ContentTypeTag);
            WriteData(script, Encoding.UTF8.GetBytes(inscription.ContentType));
        }

        if (inscription.Parent is { Length: > 0 } parent)
        {
            WriteTag(script, Inscription.ParentTag);
            WriteData(script, parent);
        }

        if (inscription.Metadata is { Length: > 0 } metadata)
        {
            WriteTag(script, Inscription.MetadataTag);
            WriteData(script, metadata);
        }

        script.Add(OpFalse);
        if (inscription.Body.Length > 0)
            WriteData(script, inscription.Body);
        script.Add(OpEndIf);
        return script.ToArray();
    }

    private static void WriteTag(List<byte> script, int tag)
    {
        if (tag is >= 1 and <= 16)
            script.Add((byte)(0x50 + tag));
        else
            WriteData(script, [(byte)tag]);
    }

    private static void WriteData(List<byte> script, ReadOnlySpan<byte> data)
    {
        if (data.Length <= 75)
        {
            script.Add((byte)data.Length);
        }
        else if (data.Length <= byte.MaxValue)
        {
            script.Add(OpPushData1);
            script.Add((byte)data.Length);
        }
        else if (data.Length <= ushort.MaxValue)
        {
            script.Add(OpPushData2);
            script.Add((byte)data.Length);
            script.Add((byte)(data.Length >> 8));
        }
        else
        {
            script.Add(OpPushData4);
            script.Add((byte)data.Length);
            script.Add((byte)(data.Length >> 8));
            script.Add((byte)(data.Length >> 16));
            script.Add((byte)(data.Length >> 24));
        }

        foreach (byte value in data)
            script.Add(value);
    }

    private static bool TryReadEnvelope(ReadOnlySpan<byte> script, int start, out int end, out Inscription? inscription)
    {
        end = start;
        inscription = null;
        int offset = start + 2;
        if (!TryReadData(script, ref offset, out byte[]? protocol) || !protocol.AsSpan().SequenceEqual(Protocol))
            return false;

        string? contentType = null;
        byte[]? parent = null;
        byte[]? metadata = null;
        while (offset < script.Length && script[offset] != OpEndIf)
        {
            if (script[offset] == OpFalse)
            {
                offset++;
                var body = new List<byte>();
                while (offset < script.Length && script[offset] != OpEndIf)
                {
                    if (!TryReadData(script, ref offset, out byte[]? chunk))
                        return false;
                    body.AddRange(chunk!);
                }

                if (offset >= script.Length || script[offset] != OpEndIf)
                    return false;
                end = offset + 1;
                inscription = new Inscription(contentType, body.ToArray(), metadata ?? [], parent ?? []);
                return true;
            }

            if (!TryReadTag(script, ref offset, out int tag) || !TryReadData(script, ref offset, out byte[]? value))
                return false;
            if (tag == Inscription.ContentTypeTag && contentType is null)
                contentType = Encoding.UTF8.GetString(value!);
            else if (tag == Inscription.ParentTag && parent is null)
                parent = value;
            else if (tag == Inscription.MetadataTag && metadata is null)
                metadata = value;
        }

        return false;
    }

    private static Script LockingScriptAround(ReadOnlySpan<byte> script, int start, int end)
    {
        int before = start;
        int after = end;
        if (before > 0 && script[before - 1] == OpCodeSeparator)
            before--;
        if (after < script.Length && script[after] == OpCodeSeparator)
            after++;
        var locking = new byte[before + script.Length - after];
        script[..before].CopyTo(locking);
        script[after..].CopyTo(locking.AsSpan(before));
        return new Script(locking);
    }

    private static bool TryReadTag(ReadOnlySpan<byte> script, ref int offset, out int tag)
    {
        tag = 0;
        if (offset >= script.Length)
            return false;
        byte opcode = script[offset];
        if (opcode is >= 0x51 and <= 0x60)
        {
            tag = opcode - 0x50;
            offset++;
            return true;
        }

        if (!TryReadData(script, ref offset, out byte[]? data) || data!.Length != 1)
            return false;
        tag = data[0];
        return true;
    }

    private static bool TryReadData(ReadOnlySpan<byte> script, ref int offset, out byte[]? data)
    {
        data = null;
        if (offset >= script.Length)
            return false;
        byte opcode = script[offset];
        if (opcode == OpFalse)
        {
            offset++;
            data = [];
            return true;
        }

        if (opcode is >= 0x51 and <= 0x60)
        {
            offset++;
            data = [(byte)(opcode - 0x50)];
            return true;
        }

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

    private static bool TrySkip(ReadOnlySpan<byte> script, ref int offset)
    {
        if (script[offset] is > 0 and < OpPushData1 or OpPushData1 or OpPushData2 or OpPushData4)
            return TryReadData(script, ref offset, out _);
        offset++;
        return true;
    }
}
