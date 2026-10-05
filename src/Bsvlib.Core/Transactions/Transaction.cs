using System.Buffers.Binary;

namespace Bsvlib.Core;

public sealed class TxInput
{
    public TxInput(OutPoint previousOutput, Script unlockingScript, uint sequence)
    {
        PreviousOutput = previousOutput;
        UnlockingScript = unlockingScript ?? throw new ArgumentNullException(nameof(unlockingScript));
        Sequence = sequence;
    }

    public OutPoint PreviousOutput { get; }

    public Script UnlockingScript { get; }

    public uint Sequence { get; }

    public int GetSerializedLength()
    {
        int scriptLength = UnlockingScript.Bytes.Length;
        return OutPoint.Size + VarInt.GetSize((ulong)scriptLength) + scriptLength + 4;
    }

    public int Write(Span<byte> destination)
    {
        int needed = GetSerializedLength();
        if (destination.Length < needed)
            throw new ArgumentException($"Destination must be at least {needed} bytes.", nameof(destination));

        PreviousOutput.Write(destination);
        int offset = OutPoint.Size;
        offset += VarInt.Write(destination[offset..], (ulong)UnlockingScript.Bytes.Length);
        UnlockingScript.Bytes.Span.CopyTo(destination[offset..]);
        offset += UnlockingScript.Bytes.Length;
        BinaryPrimitives.WriteUInt32LittleEndian(destination[offset..], Sequence);
        return offset + 4;
    }
}

public sealed class TxOutput
{
    public TxOutput(Satoshis value, Script lockingScript)
    {
        Value = value;
        LockingScript = lockingScript ?? throw new ArgumentNullException(nameof(lockingScript));
    }

    public Satoshis Value { get; }

    public Script LockingScript { get; }

    public int GetSerializedLength()
    {
        int scriptLength = LockingScript.Bytes.Length;
        return 8 + VarInt.GetSize((ulong)scriptLength) + scriptLength;
    }

    public int Write(Span<byte> destination)
    {
        int needed = GetSerializedLength();
        if (destination.Length < needed)
            throw new ArgumentException($"Destination must be at least {needed} bytes.", nameof(destination));

        BinaryPrimitives.WriteInt64LittleEndian(destination, Value.Value);
        int offset = 8 + VarInt.Write(destination[8..], (ulong)LockingScript.Bytes.Length);
        LockingScript.Bytes.Span.CopyTo(destination[offset..]);
        return offset + LockingScript.Bytes.Length;
    }
}

/// <summary>不可变交易。交易号是序列化字节的双重 SHA-256，显示时反转。</summary>
public sealed class Transaction
{
    private readonly TxInput[] _inputs;
    private readonly TxOutput[] _outputs;
    private byte[]? _bytes;
    private TxId _id;
    private bool _hasId;

    public Transaction(int version, IReadOnlyList<TxInput> inputs, IReadOnlyList<TxOutput> outputs, uint lockTime)
    {
        ArgumentNullException.ThrowIfNull(inputs);
        ArgumentNullException.ThrowIfNull(outputs);
        Version = version;
        LockTime = lockTime;
        _inputs = Copy(inputs);
        _outputs = Copy(outputs);
    }

    public int Version { get; }

    public IReadOnlyList<TxInput> Inputs => _inputs;

    public IReadOnlyList<TxOutput> Outputs => _outputs;

    public uint LockTime { get; }

    public TxId Id
    {
        get
        {
            if (_hasId)
                return _id;
            _bytes ??= Serialize();
            _id = TxId.FromWire(Bsvlib.Crypto.Hash256.Compute(_bytes));
            _hasId = true;
            return _id;
        }
    }

    public int GetSerializedLength()
    {
        int length = 8 + VarInt.GetSize((ulong)_inputs.Length) + VarInt.GetSize((ulong)_outputs.Length);
        foreach (TxInput input in _inputs)
            length += input.GetSerializedLength();
        foreach (TxOutput output in _outputs)
            length += output.GetSerializedLength();
        return length;
    }

    public int Write(Span<byte> destination)
    {
        byte[] bytes = _bytes ??= Serialize();
        if (destination.Length < bytes.Length)
            throw new ArgumentException($"Destination must be at least {bytes.Length} bytes.", nameof(destination));
        bytes.CopyTo(destination);
        return bytes.Length;
    }

    public byte[] ToBytes()
    {
        byte[] bytes = _bytes ??= Serialize();
        return (byte[])bytes.Clone();
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out Transaction? transaction, out int bytesRead)
    {
        transaction = null;
        bytesRead = 0;
        var reader = new SpanReader(data);
        if (!reader.TryReadInt32(out int version) || !reader.TryReadVarInt(out ulong inputCount))
            return false;
        if (inputCount > (ulong)(reader.Remaining / 41) || inputCount > int.MaxValue)
            return false;

        var inputs = new TxInput[(int)inputCount];
        for (int i = 0; i < inputs.Length; i++)
        {
            if (!TryReadInput(ref reader, out TxInput? input))
                return false;
            inputs[i] = input!;
        }

        if (!reader.TryReadVarInt(out ulong outputCount))
            return false;
        if (outputCount > (ulong)(reader.Remaining / 9) || outputCount > int.MaxValue)
            return false;

        var outputs = new TxOutput[(int)outputCount];
        for (int i = 0; i < outputs.Length; i++)
        {
            if (!TryReadOutput(ref reader, out TxOutput? output))
                return false;
            outputs[i] = output!;
        }

        if (!reader.TryReadUInt32(out uint lockTime))
            return false;

        transaction = new Transaction(version, inputs, outputs, lockTime);
        bytesRead = reader.Consumed;
        return true;
    }

    private byte[] Serialize()
    {
        var buffer = new byte[GetSerializedLength()];
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(buffer, Version);
        offset = 4;
        offset += VarInt.Write(buffer.AsSpan(offset), (ulong)_inputs.Length);
        foreach (TxInput input in _inputs)
            offset += input.Write(buffer.AsSpan(offset));
        offset += VarInt.Write(buffer.AsSpan(offset), (ulong)_outputs.Length);
        foreach (TxOutput output in _outputs)
            offset += output.Write(buffer.AsSpan(offset));
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(offset), LockTime);
        return buffer;
    }

    private static bool TryReadInput(ref SpanReader reader, out TxInput? input)
    {
        input = null;
        if (!reader.TryReadBytes(TxId.Size, out ReadOnlySpan<byte> hash) || !reader.TryReadUInt32(out uint index))
            return false;
        if (!reader.TryReadVarInt(out ulong scriptLength) || scriptLength > int.MaxValue)
            return false;
        if (!reader.TryReadBytes((int)scriptLength, out ReadOnlySpan<byte> script) || !reader.TryReadUInt32(out uint sequence))
            return false;

        input = new TxInput(new OutPoint(TxId.FromWire(hash), index), new Script(script), sequence);
        return true;
    }

    private static bool TryReadOutput(ref SpanReader reader, out TxOutput? output)
    {
        output = null;
        if (!reader.TryReadInt64(out long value) || !Satoshis.TryCreate(value, out Satoshis amount))
            return false;
        if (!reader.TryReadVarInt(out ulong scriptLength) || scriptLength > int.MaxValue)
            return false;
        if (!reader.TryReadBytes((int)scriptLength, out ReadOnlySpan<byte> script))
            return false;

        output = new TxOutput(amount, new Script(script));
        return true;
    }

    private static T[] Copy<T>(IReadOnlyList<T> source)
    {
        var copy = new T[source.Count];
        for (int i = 0; i < copy.Length; i++)
            copy[i] = source[i] ?? throw new ArgumentException("Collection contains a null entry.", nameof(source));
        return copy;
    }
}
