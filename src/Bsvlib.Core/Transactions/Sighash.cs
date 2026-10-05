using System.Buffers.Binary;
using Bsvlib.Crypto;

namespace Bsvlib.Core;

/// <summary>
/// 签名哈希类型。低 5 位是 ALL / NONE / SINGLE 之一。
/// 未设置 <see cref="Chronicle"/> 时使用带 ForkId 的 BIP143 式摘要；设置后使用原始交易摘要。
/// </summary>
[Flags]
public enum SighashType : uint
{
    All = 1,
    None = 2,
    Single = 3,
    Chronicle = 0x20,
    ForkId = 0x40,
    AnyoneCanPay = 0x80,
}

/// <summary>BSV 交易摘要。默认路径是 SIGHASH_FORKID；Chronicle 的 0x20 选择原始摘要。</summary>
public static class Sighash
{
    private const uint BaseMask = 0x1F;

    public static byte[] Digest(Transaction transaction, int input, Script previousLockingScript, Satoshis previousValue, SighashType sighash)
    {
        if (!TryGetPreimage(transaction, input, previousLockingScript, previousValue, sighash, out byte[]? preimage))
        {
            var one = new byte[Hash256.Size];
            one[0] = 1;
            return one;
        }

        return Hash256.Compute(preimage);
    }

    public static bool TryGetPreimage(
        Transaction transaction,
        int input,
        Script previousLockingScript,
        Satoshis previousValue,
        SighashType sighash,
        out byte[] preimage)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        ArgumentNullException.ThrowIfNull(previousLockingScript);
        if ((uint)input >= (uint)transaction.Inputs.Count)
            throw new ArgumentOutOfRangeException(nameof(input));

        if (UsesOriginalDigest(sighash) && IsSingleBug(transaction, input, sighash))
        {
            preimage = [];
            return false;
        }

        Script scriptCode = previousLockingScript.WithoutCodeSeparators();
        preimage = UsesOriginalDigest(sighash)
            ? OriginalPreimage(transaction, input, scriptCode, sighash)
            : ForkIdPreimage(transaction, input, scriptCode, previousValue, sighash);
        return true;
    }

    public static bool UsesOriginalDigest(SighashType sighash) => (sighash & SighashType.Chronicle) != 0;

    private static bool IsSingleBug(Transaction transaction, int input, SighashType sighash) =>
        BaseType(sighash) == SighashType.Single && input >= transaction.Outputs.Count;

    private static SighashType BaseType(SighashType sighash) => sighash & (SighashType)BaseMask;

    private static byte[] ForkIdPreimage(Transaction transaction, int input, Script scriptCode, Satoshis previousValue, SighashType sighash)
    {
        Span<byte> hashPrevouts = stackalloc byte[32];
        Span<byte> hashSequence = stackalloc byte[32];
        Span<byte> hashOutputs = stackalloc byte[32];
        WriteForkIdHashes(transaction, input, sighash, hashPrevouts, hashSequence, hashOutputs);

        int scriptLength = scriptCode.Bytes.Length;
        int size = 4 + 32 + 32 + OutPoint.Size + VarInt.GetSize((ulong)scriptLength) + scriptLength + 8 + 4 + 32 + 4 + 4;
        var preimage = new byte[size];
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(preimage, transaction.Version);
        offset = 4;
        hashPrevouts.CopyTo(preimage.AsSpan(offset));
        offset += 32;
        hashSequence.CopyTo(preimage.AsSpan(offset));
        offset += 32;
        transaction.Inputs[input].PreviousOutput.Write(preimage.AsSpan(offset));
        offset += OutPoint.Size;
        offset += VarInt.Write(preimage.AsSpan(offset), (ulong)scriptLength);
        scriptCode.Bytes.Span.CopyTo(preimage.AsSpan(offset));
        offset += scriptLength;
        BinaryPrimitives.WriteInt64LittleEndian(preimage.AsSpan(offset), previousValue.Value);
        offset += 8;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), transaction.Inputs[input].Sequence);
        offset += 4;
        hashOutputs.CopyTo(preimage.AsSpan(offset));
        offset += 32;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), transaction.LockTime);
        offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), (uint)sighash);
        return preimage;
    }

    private static void WriteForkIdHashes(
        Transaction transaction,
        int input,
        SighashType sighash,
        Span<byte> hashPrevouts,
        Span<byte> hashSequence,
        Span<byte> hashOutputs)
    {
        hashPrevouts.Clear();
        hashSequence.Clear();
        hashOutputs.Clear();
        bool anyoneCanPay = (sighash & SighashType.AnyoneCanPay) != 0;
        SighashType baseType = BaseType(sighash);

        if (!anyoneCanPay)
        {
            var prevouts = new byte[transaction.Inputs.Count * OutPoint.Size];
            for (int i = 0; i < transaction.Inputs.Count; i++)
                transaction.Inputs[i].PreviousOutput.Write(prevouts.AsSpan(i * OutPoint.Size));
            Hash256.Write(prevouts, hashPrevouts);
        }

        if (!anyoneCanPay && baseType is not SighashType.Single and not SighashType.None)
        {
            var sequences = new byte[transaction.Inputs.Count * 4];
            for (int i = 0; i < transaction.Inputs.Count; i++)
                BinaryPrimitives.WriteUInt32LittleEndian(sequences.AsSpan(i * 4), transaction.Inputs[i].Sequence);
            Hash256.Write(sequences, hashSequence);
        }

        if (baseType is not SighashType.Single and not SighashType.None)
        {
            Hash256.Write(SerializeOutputs(transaction.Outputs), hashOutputs);
        }
        else if (baseType == SighashType.Single && input < transaction.Outputs.Count)
        {
            TxOutput output = transaction.Outputs[input];
            var one = new byte[output.GetSerializedLength()];
            output.Write(one);
            Hash256.Write(one, hashOutputs);
        }
    }

    private static byte[] OriginalPreimage(Transaction transaction, int input, Script scriptCode, SighashType sighash)
    {
        SighashType baseType = BaseType(sighash);
        bool anyoneCanPay = (sighash & SighashType.AnyoneCanPay) != 0;
        bool blankOtherSequences = baseType is SighashType.None or SighashType.Single;

        int inputCount = anyoneCanPay ? 1 : transaction.Inputs.Count;
        var inputs = new (OutPoint Previous, Script Script, uint Sequence)[inputCount];
        for (int i = 0; i < inputCount; i++)
        {
            int source = anyoneCanPay ? input : i;
            TxInput current = transaction.Inputs[source];
            uint sequence = blankOtherSequences && source != input ? 0 : current.Sequence;
            Script script = source == input ? scriptCode : Script.Empty;
            inputs[i] = (current.PreviousOutput, script, sequence);
        }

        int outputCount = baseType switch
        {
            SighashType.None => 0,
            SighashType.Single => input + 1,
            _ => transaction.Outputs.Count,
        };

        int length = 12;
        length += VarInt.GetSize((ulong)inputCount);
        foreach ((OutPoint previous, Script script, uint _) in inputs)
        {
            int scriptLength = script.Bytes.Length;
            length += OutPoint.Size + VarInt.GetSize((ulong)scriptLength) + scriptLength + 4;
        }

        length += VarInt.GetSize((ulong)outputCount);
        if (baseType == SighashType.Single)
        {
            for (int i = 0; i < input; i++)
                length += 8 + 1;
            length += transaction.Outputs[input].GetSerializedLength();
        }
        else if (baseType != SighashType.None)
        {
            for (int i = 0; i < outputCount; i++)
                length += transaction.Outputs[i].GetSerializedLength();
        }

        var preimage = new byte[length];
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(preimage, transaction.Version);
        offset = 4;
        offset += VarInt.Write(preimage.AsSpan(offset), (ulong)inputCount);
        foreach ((OutPoint previous, Script script, uint sequence) in inputs)
        {
            previous.Write(preimage.AsSpan(offset));
            offset += OutPoint.Size;
            offset += VarInt.Write(preimage.AsSpan(offset), (ulong)script.Bytes.Length);
            script.Bytes.Span.CopyTo(preimage.AsSpan(offset));
            offset += script.Bytes.Length;
            BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), sequence);
            offset += 4;
        }

        offset += VarInt.Write(preimage.AsSpan(offset), (ulong)outputCount);
        if (baseType == SighashType.Single)
        {
            for (int i = 0; i < input; i++)
            {
                BinaryPrimitives.WriteInt64LittleEndian(preimage.AsSpan(offset), -1);
                offset += 8;
                preimage[offset++] = 0;
            }

            offset += transaction.Outputs[input].Write(preimage.AsSpan(offset));
        }
        else if (baseType != SighashType.None)
        {
            for (int i = 0; i < outputCount; i++)
                offset += transaction.Outputs[i].Write(preimage.AsSpan(offset));
        }

        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), transaction.LockTime);
        offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), (uint)sighash);
        offset += 4;
        if (offset != preimage.Length)
            throw new InvalidOperationException("Original sighash preimage size was calculated incorrectly.");
        return preimage;
    }

    private static byte[] SerializeOutputs(IReadOnlyList<TxOutput> outputs)
    {
        int length = 0;
        for (int i = 0; i < outputs.Count; i++)
            length += outputs[i].GetSerializedLength();
        var buffer = new byte[length];
        int offset = 0;
        for (int i = 0; i < outputs.Count; i++)
            offset += outputs[i].Write(buffer.AsSpan(offset));
        return buffer;
    }
}
