using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Bsvlib.Core;

namespace Bsvlib.P2P;

/// <summary>
/// block 消息。从连接读取时先给出区块头，交易由 <see cref="ReadTransactionsAsync"/> 逐笔吐出。
/// </summary>
public sealed class BlockMessage : NetworkMessage
{
    private readonly Transaction[]? _transactions;
    private readonly Stream? _stream;
    private readonly IncrementalHash? _hash;
    private readonly uint _checksum;
    private int _payloadRemaining;
    private bool _started;

    private BlockMessage(BlockHeader header, Transaction[] transactions)
    {
        Header = header;
        _transactions = transactions;
    }

    private BlockMessage(BlockHeader header, Stream stream, IncrementalHash hash, uint checksum, int payloadRemaining)
    {
        Header = header;
        _stream = stream;
        _hash = hash;
        _checksum = checksum;
        _payloadRemaining = payloadRemaining;
    }

    public override string Command => "block";

    public BlockHeader Header { get; }

    public override int GetPayloadLength()
    {
        if (_transactions is null)
            throw new InvalidOperationException("A streamed block cannot be measured until its transactions are loaded.");
        int length = BlockHeader.Size + VarInt.GetSize((ulong)_transactions.Length);
        foreach (Transaction transaction in _transactions)
            length += transaction.GetSerializedLength();
        return length;
    }

    public override void WritePayload(Span<byte> destination)
    {
        if (_transactions is null)
            throw new InvalidOperationException("A streamed block cannot be written until its transactions are loaded.");
        Header.Write(destination);
        int offset = BlockHeader.Size + VarInt.Write(destination[BlockHeader.Size..], (ulong)_transactions.Length);
        foreach (Transaction transaction in _transactions)
            offset += transaction.Write(destination[offset..]);
    }

    public static BlockMessage? TryRead(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < BlockHeader.Size || !BlockHeader.TryRead(payload, out BlockHeader? header))
            return null;
        if (!VarInt.TryRead(payload[BlockHeader.Size..], out ulong count, out int countSize) || count > int.MaxValue)
            return null;
        int offset = BlockHeader.Size + countSize;
        var transactions = new Transaction[count];
        for (int i = 0; i < transactions.Length; i++)
        {
            if (!Transaction.TryRead(payload[offset..], out Transaction? transaction, out int used))
                return null;
            transactions[i] = transaction!;
            offset += used;
        }

        return offset == payload.Length ? new BlockMessage(header!, transactions) : null;
    }

    public static async ValueTask<BlockMessage> ReadStreamingAsync(Stream stream, int payloadLength, uint checksum, CancellationToken cancellationToken)
    {
        if (payloadLength < BlockHeader.Size)
            throw new InvalidDataException("Block payload is shorter than a header.");
        var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var headerBytes = new byte[BlockHeader.Size];
        await StreamBytes.ReadExactlyAsync(stream, headerBytes, cancellationToken).ConfigureAwait(false);
        hash.AppendData(headerBytes);
        if (!BlockHeader.TryRead(headerBytes, out BlockHeader? header))
            throw new InvalidDataException("Block header is invalid.");
        return new BlockMessage(header!, stream, hash, checksum, payloadLength - BlockHeader.Size);
    }

    public async IAsyncEnumerable<Transaction> ReadTransactionsAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        if (_transactions is not null)
        {
            foreach (Transaction transaction in _transactions)
                yield return transaction;
            yield break;
        }

        if (_started)
            throw new InvalidOperationException("Block transactions can only be read once.");
        _started = true;
        var pending = new List<byte>();
        int pendingOffset = 0;
        ulong count = await ReadVarIntAsync(pending, () => PullAsync(pending, cancellationToken)).ConfigureAwait(false);
        if (count > int.MaxValue)
            throw new InvalidDataException("Block contains too many transactions.");
        for (ulong i = 0; i < count; i++)
        {
            Transaction transaction = await ReadTransactionAsync(pending, () => PullAsync(pending, cancellationToken), () => pendingOffset, value => pendingOffset = value).ConfigureAwait(false);
            if (pendingOffset > 8192)
            {
                pending.RemoveRange(0, pendingOffset);
                pendingOffset = 0;
            }

            yield return transaction;
        }

        if (pendingOffset != pending.Count || _payloadRemaining != 0)
            throw new InvalidDataException("Block payload has trailing bytes.");
        FinishChecksum();
    }

    private async ValueTask PullAsync(List<byte> pending, CancellationToken cancellationToken)
    {
        if (_payloadRemaining == 0)
            throw new EndOfStreamException();
        int take = Math.Min(4096, _payloadRemaining);
        var chunk = new byte[take];
        await StreamBytes.ReadExactlyAsync(_stream!, chunk, cancellationToken).ConfigureAwait(false);
        _hash!.AppendData(chunk);
        pending.AddRange(chunk);
        _payloadRemaining -= take;
    }

    private void FinishChecksum()
    {
        byte[] first = _hash!.GetHashAndReset();
        Span<byte> second = stackalloc byte[32];
        SHA256.HashData(first, second);
        uint actual = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(second);
        if (actual != _checksum)
            throw new InvalidDataException("Block checksum does not match.");
    }

    private static async ValueTask<ulong> ReadVarIntAsync(List<byte> pending, Func<ValueTask> pull)
    {
        while (pending.Count == 0)
            await pull().ConfigureAwait(false);
        int size = pending[0] switch
        {
            < 0xFD => 1,
            0xFD => 3,
            0xFE => 5,
            _ => 9,
        };
        while (pending.Count < size)
            await pull().ConfigureAwait(false);
        if (!VarInt.TryRead(CollectionsMarshal.AsSpan(pending)[..size], out ulong value, out _))
            throw new InvalidDataException("Invalid transaction count.");
        pending.RemoveRange(0, size);
        return value;
    }

    private static async ValueTask<Transaction> ReadTransactionAsync(List<byte> pending, Func<ValueTask> pull, Func<int> offset, Action<int> setOffset)
    {
        while (true)
        {
            ReadOnlySpan<byte> available = CollectionsMarshal.AsSpan(pending)[offset()..];
            if (available.Length > 0 && Transaction.TryRead(available, out Transaction? transaction, out int used))
            {
                setOffset(offset() + used);
                return transaction!;
            }

            int before = pending.Count;
            await pull().ConfigureAwait(false);
            if (pending.Count == before)
                throw new InvalidDataException("Transaction ended before it could be parsed.");
        }
    }
}
