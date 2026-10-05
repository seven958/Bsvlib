using System.Buffers.Binary;
using Bsvlib.Crypto;

namespace Bsvlib.Core;

/// <summary>80 字节区块头。哈希的显示规则与交易号相同。</summary>
public sealed class BlockHeader
{
    public const int Size = 80;

    private byte[]? _bytes;
    private TxId _hash;
    private bool _hasHash;

    public BlockHeader(int version, TxId previousBlock, TxId merkleRoot, uint time, uint bits, uint nonce)
    {
        Version = version;
        PreviousBlock = previousBlock;
        MerkleRoot = merkleRoot;
        Time = time;
        Bits = bits;
        Nonce = nonce;
    }

    public int Version { get; }

    public TxId PreviousBlock { get; }

    public TxId MerkleRoot { get; }

    public uint Time { get; }

    public uint Bits { get; }

    public uint Nonce { get; }

    public TxId Hash
    {
        get
        {
            if (_hasHash)
                return _hash;
            _bytes ??= Serialize();
            _hash = TxId.FromWire(Hash256.Compute(_bytes));
            _hasHash = true;
            return _hash;
        }
    }

    public int Write(Span<byte> destination)
    {
        byte[] bytes = _bytes ??= Serialize();
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));
        bytes.CopyTo(destination);
        return Size;
    }

    public byte[] ToBytes()
    {
        _bytes ??= Serialize();
        return (byte[])_bytes.Clone();
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out BlockHeader? header)
    {
        header = null;
        if (data.Length < Size)
            return false;

        int version = BinaryPrimitives.ReadInt32LittleEndian(data);
        TxId previous = TxId.FromWire(data.Slice(4, TxId.Size));
        TxId merkle = TxId.FromWire(data.Slice(36, TxId.Size));
        uint time = BinaryPrimitives.ReadUInt32LittleEndian(data[68..]);
        uint bits = BinaryPrimitives.ReadUInt32LittleEndian(data[72..]);
        uint nonce = BinaryPrimitives.ReadUInt32LittleEndian(data[76..]);
        header = new BlockHeader(version, previous, merkle, time, bits, nonce);
        return true;
    }

    private byte[] Serialize()
    {
        var buffer = new byte[Size];
        BinaryPrimitives.WriteInt32LittleEndian(buffer, Version);
        PreviousBlock.WriteWire(buffer.AsSpan(4));
        MerkleRoot.WriteWire(buffer.AsSpan(36));
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(68), Time);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(72), Bits);
        BinaryPrimitives.WriteUInt32LittleEndian(buffer.AsSpan(76), Nonce);
        return buffer;
    }
}
