using System.Buffers.Binary;
using Bsvlib.Core;

namespace Bsvlib.Spv;

public interface IChainTracker
{
    bool IsValidRoot(long blockHeight, TxId merkleRoot);
}

public sealed class BeefTransaction
{
    public BeefTransaction(Transaction transaction, int? bumpIndex)
    {
        Transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));
        if (bumpIndex is < 0)
            throw new ArgumentOutOfRangeException(nameof(bumpIndex));
        BumpIndex = bumpIndex;
    }

    public Transaction Transaction { get; }

    public int? BumpIndex { get; }
}

/// <summary>BRC-62 BEEF。版本字 4022206465 的小端字节是 0100BEEF。</summary>
public sealed class Beef
{
    public const uint Version1 = 0xEFBE_0001;

    public const uint AtomicPrefix = 0x0101_0101;

    private readonly Bump[] _bumps;
    private readonly BeefTransaction[] _transactions;

    public Beef(IReadOnlyList<Bump> bumps, IReadOnlyList<BeefTransaction> transactions)
    {
        ArgumentNullException.ThrowIfNull(bumps);
        ArgumentNullException.ThrowIfNull(transactions);
        _bumps = bumps.ToArray();
        _transactions = transactions.ToArray();
        foreach (BeefTransaction tx in _transactions)
        {
            if (tx.BumpIndex is int index && (uint)index >= (uint)_bumps.Length)
                throw new ArgumentException("BUMP index is outside the path list.", nameof(transactions));
        }
    }

    public IReadOnlyList<Bump> Bumps => _bumps;

    public IReadOnlyList<BeefTransaction> Transactions => _transactions;

    public byte[] ToBytes()
    {
        using var stream = new MemoryStream();
        Span<byte> version = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(version, Version1);
        stream.Write(version);
        WriteVarInt(stream, (ulong)_bumps.Length);
        foreach (Bump bump in _bumps)
            stream.Write(bump.ToBytes());
        WriteVarInt(stream, (ulong)_transactions.Length);
        foreach (BeefTransaction item in _transactions)
        {
            stream.Write(item.Transaction.ToBytes());
            if (item.BumpIndex is int index)
            {
                stream.WriteByte(1);
                WriteVarInt(stream, (ulong)index);
            }
            else
            {
                stream.WriteByte(0);
            }
        }

        return stream.ToArray();
    }

    public byte[] ToAtomicBytes(TxId subject)
    {
        using var stream = new MemoryStream();
        Span<byte> prefix = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(prefix, AtomicPrefix);
        stream.Write(prefix);
        var txId = new byte[TxId.Size];
        subject.WriteWire(txId);
        stream.Write(txId);
        stream.Write(ToBytes());
        return stream.ToArray();
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out Beef? beef, out int bytesRead) =>
        TryReadCore(data, out beef, out bytesRead);

    public static bool TryReadAtomic(ReadOnlySpan<byte> data, out TxId subject, out Beef? beef, out int bytesRead)
    {
        subject = default;
        beef = null;
        bytesRead = 0;
        if (data.Length < 4 + TxId.Size)
            return false;
        if (BinaryPrimitives.ReadUInt32LittleEndian(data) != AtomicPrefix)
            return false;
        subject = TxId.FromWire(data.Slice(4, TxId.Size));
        if (!TryReadCore(data[(4 + TxId.Size)..], out beef, out int beefBytes))
            return false;
        bytesRead = 4 + TxId.Size + beefBytes;
        return true;
    }

    public bool TryValidate(IChainTracker tracker) => TryValidate(tracker, subject: null);

    public bool TryValidateAtomic(IChainTracker tracker, TxId subject)
    {
        if (!Contains(subject) || !IsAncestorClosure(subject))
            return false;
        return TryValidate(tracker, subject);
    }

    private bool TryValidate(IChainTracker tracker, TxId? subject)
    {
        ArgumentNullException.ThrowIfNull(tracker);
        var valid = new HashSet<TxId>();
        var previous = new Dictionary<TxId, Transaction>();
        foreach (BeefTransaction item in _transactions)
        {
            if (item.BumpIndex is int index)
            {
                if (!_bumps[index].TryComputeRoot(item.Transaction.Id, out TxId root) || !tracker.IsValidRoot(_bumps[index].BlockHeight, root))
                    return false;
            }
            else if (!SpendsValidParents(item.Transaction, valid, previous))
            {
                return false;
            }

            valid.Add(item.Transaction.Id);
            previous[item.Transaction.Id] = item.Transaction;
        }

        return subject is null || valid.Contains(subject.Value);
    }

    private static bool SpendsValidParents(Transaction transaction, HashSet<TxId> valid, Dictionary<TxId, Transaction> previous)
    {
        for (int i = 0; i < transaction.Inputs.Count; i++)
        {
            TxInput input = transaction.Inputs[i];
            if (!valid.Contains(input.PreviousOutput.TxId) || !previous.TryGetValue(input.PreviousOutput.TxId, out Transaction? parent))
                return false;
            if (input.PreviousOutput.Index >= parent.Outputs.Count)
                return false;

            TxOutput output = parent.Outputs[(int)input.PreviousOutput.Index];
            var checker = new TransactionSignatureChecker(transaction, i, output.Value);
            if (!ScriptInterpreter.Verify(input.UnlockingScript, output.LockingScript, checker, out _))
                return false;
        }

        return true;
    }

    private bool Contains(TxId txId)
    {
        foreach (BeefTransaction item in _transactions)
        {
            if (item.Transaction.Id.Equals(txId))
                return true;
        }

        return false;
    }

    private bool IsAncestorClosure(TxId subject)
    {
        var package = new Dictionary<TxId, Transaction>();
        foreach (BeefTransaction item in _transactions)
            package[item.Transaction.Id] = item.Transaction;

        var reached = new HashSet<TxId> { subject };
        var pending = new Queue<TxId>();
        pending.Enqueue(subject);
        while (pending.Count > 0)
        {
            TxId id = pending.Dequeue();
            if (!package.TryGetValue(id, out Transaction? transaction))
                return false;
            foreach (TxInput input in transaction.Inputs)
            {
                TxId parent = input.PreviousOutput.TxId;
                if (package.ContainsKey(parent) && reached.Add(parent))
                    pending.Enqueue(parent);
            }
        }

        return reached.Count == package.Count;
    }

    private static bool TryReadCore(ReadOnlySpan<byte> data, out Beef? beef, out int bytesRead)
    {
        beef = null;
        bytesRead = 0;
        if (data.Length < 4 || BinaryPrimitives.ReadUInt32LittleEndian(data) != Version1)
            return false;

        int offset = 4;
        if (!TryReadVarInt(data, ref offset, out ulong bumpCount) || bumpCount > int.MaxValue)
            return false;
        var bumps = new Bump[bumpCount];
        for (int i = 0; i < bumps.Length; i++)
        {
            if (!Bump.TryRead(data[offset..], out Bump? bump, out int consumed))
                return false;
            bumps[i] = bump!;
            offset += consumed;
        }

        if (!TryReadVarInt(data, ref offset, out ulong txCount) || txCount > int.MaxValue)
            return false;
        var transactions = new BeefTransaction[txCount];
        for (int i = 0; i < transactions.Length; i++)
        {
            if (!Transaction.TryRead(data[offset..], out Transaction? transaction, out int consumed))
                return false;
            offset += consumed;
            if (offset >= data.Length)
                return false;
            byte hasBump = data[offset++];
            int? bumpIndex = null;
            if (hasBump == 1)
            {
                if (!TryReadVarInt(data, ref offset, out ulong index) || index >= bumpCount)
                    return false;
                bumpIndex = (int)index;
            }
            else if (hasBump != 0)
            {
                return false;
            }

            transactions[i] = new BeefTransaction(transaction!, bumpIndex);
        }

        beef = new Beef(bumps, transactions);
        bytesRead = offset;
        return true;
    }

    private static bool TryReadVarInt(ReadOnlySpan<byte> data, ref int offset, out ulong value)
    {
        if (!VarInt.TryRead(data[offset..], out value, out int consumed))
            return false;
        offset += consumed;
        return true;
    }

    private static void WriteVarInt(Stream stream, ulong value)
    {
        Span<byte> buffer = stackalloc byte[9];
        int written = VarInt.Write(buffer, value);
        stream.Write(buffer[..written]);
    }
}
