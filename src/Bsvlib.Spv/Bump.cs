using Bsvlib.Core;

namespace Bsvlib.Spv;

public readonly record struct BumpLeaf(long Offset, bool IsTxId, bool Duplicate, TxId? Hash);

/// <summary>BRC-74 BUMP。哈希的二进制形式是链上字节序，显示十六进制与交易号相同。</summary>
public sealed class Bump
{
    public const int MaxTreeHeight = 64;

    private readonly BumpLeaf[][] _levels;

    public Bump(long blockHeight, IReadOnlyList<IReadOnlyList<BumpLeaf>> levels)
    {
        if (blockHeight < 0)
            throw new ArgumentOutOfRangeException(nameof(blockHeight));
        ArgumentNullException.ThrowIfNull(levels);
        if (levels.Count is 0 or > MaxTreeHeight)
            throw new ArgumentException("Tree height must be between 1 and 64.", nameof(levels));

        BlockHeight = blockHeight;
        _levels = new BumpLeaf[levels.Count][];
        for (int i = 0; i < levels.Count; i++)
            _levels[i] = levels[i].OrderBy(leaf => leaf.Offset).ToArray();
    }

    public long BlockHeight { get; }

    public IReadOnlyList<IReadOnlyList<BumpLeaf>> Levels => _levels;

    public byte[] ToBytes()
    {
        using var stream = new MemoryStream();
        WriteVarInt(stream, (ulong)BlockHeight);
        stream.WriteByte((byte)_levels.Length);
        foreach (BumpLeaf[] level in _levels)
        {
            WriteVarInt(stream, (ulong)level.Length);
            foreach (BumpLeaf leaf in level)
            {
                WriteVarInt(stream, (ulong)leaf.Offset);
                byte flags = (byte)((leaf.Duplicate ? 1 : 0) | (leaf.IsTxId ? 2 : 0));
                stream.WriteByte(flags);
                if (!leaf.Duplicate)
                {
                    var hash = new byte[TxId.Size];
                    (leaf.Hash ?? throw new InvalidOperationException("A non-duplicate leaf needs a hash.")).WriteWire(hash);
                    stream.Write(hash);
                }
            }
        }

        return stream.ToArray();
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out Bump? bump, out int bytesRead)
    {
        bump = null;
        bytesRead = 0;
        int offset = 0;
        if (!TryReadVarInt(data, ref offset, out ulong height) || height > long.MaxValue)
            return false;
        if (offset >= data.Length)
            return false;
        int treeHeight = data[offset++];
        if (treeHeight is 0 or > MaxTreeHeight)
            return false;

        var levels = new BumpLeaf[treeHeight][];
        for (int level = 0; level < treeHeight; level++)
        {
            if (!TryReadVarInt(data, ref offset, out ulong leafCount) || leafCount > int.MaxValue)
                return false;
            var leaves = new BumpLeaf[leafCount];
            for (int i = 0; i < leaves.Length; i++)
            {
                if (!TryReadVarInt(data, ref offset, out ulong leafOffset) || leafOffset > long.MaxValue || offset >= data.Length)
                    return false;
                byte flags = data[offset++];
                if (flags > 2)
                    return false;
                bool duplicate = (flags & 1) != 0;
                TxId? hash = null;
                if (!duplicate)
                {
                    if (data.Length - offset < TxId.Size)
                        return false;
                    hash = TxId.FromWire(data.Slice(offset, TxId.Size));
                    offset += TxId.Size;
                }

                leaves[i] = new BumpLeaf((long)leafOffset, (flags & 2) != 0, duplicate, hash);
            }

            levels[level] = leaves;
        }

        bump = new Bump((long)height, levels);
        bytesRead = offset;
        return true;
    }

    public bool TryComputeRoot(TxId txId, out TxId root)
    {
        root = default;
        BumpLeaf? start = null;
        foreach (BumpLeaf leaf in _levels[0])
        {
            if (leaf.Hash is TxId hash && hash.Equals(txId) && (start is null || leaf.IsTxId))
                start = leaf;
        }

        if (start is null)
            return false;

        long index = start.Value.Offset;
        TxId working = txId;
        for (int height = 0; height < _levels.Length; height++)
        {
            long siblingOffset = (index >> height) ^ 1;
            BumpLeaf? sibling = null;
            foreach (BumpLeaf leaf in _levels[height])
            {
                if (leaf.Offset == siblingOffset)
                {
                    sibling = leaf;
                    break;
                }
            }

            if (sibling is null)
                return false;
            if (sibling.Value.Duplicate)
            {
                working = Merkle.Parent(working, working);
            }
            else if (sibling.Value.Hash is not TxId hash || hash.Equals(working))
            {
                return false;
            }
            else
            {
                working = (siblingOffset & 1) == 1 ? Merkle.Parent(working, hash) : Merkle.Parent(hash, working);
            }
        }

        root = working;
        return true;
    }

    private static bool TryReadVarInt(ReadOnlySpan<byte> data, ref int offset, out ulong value)
    {
        value = 0;
        if (!Bsvlib.Core.VarInt.TryRead(data[offset..], out value, out int consumed))
            return false;
        offset += consumed;
        return true;
    }

    private static void WriteVarInt(Stream stream, ulong value)
    {
        Span<byte> buffer = stackalloc byte[9];
        int written = Bsvlib.Core.VarInt.Write(buffer, value);
        stream.Write(buffer[..written]);
    }
}
