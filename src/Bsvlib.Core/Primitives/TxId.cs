using System.Buffers.Binary;
using System.Globalization;

namespace Bsvlib.Core;

/// <summary>
/// 32 字节哈希。内部保存链上字节序；<see cref="ToString"/> 和 <see cref="TryParse"/> 使用反转后的显示十六进制。
/// 交易号和区块哈希共用这一约定。
/// </summary>
public readonly record struct TxId
{
    public const int Size = 32;

    private readonly ulong _w0;
    private readonly ulong _w1;
    private readonly ulong _w2;
    private readonly ulong _w3;

    private TxId(ulong w0, ulong w1, ulong w2, ulong w3)
    {
        _w0 = w0;
        _w1 = w1;
        _w2 = w2;
        _w3 = w3;
    }

    public static TxId FromWire(ReadOnlySpan<byte> wire)
    {
        if (wire.Length != Size)
            throw new ArgumentException($"Wire hash must be {Size} bytes.", nameof(wire));

        return new TxId(
            BinaryPrimitives.ReadUInt64LittleEndian(wire),
            BinaryPrimitives.ReadUInt64LittleEndian(wire[8..]),
            BinaryPrimitives.ReadUInt64LittleEndian(wire[16..]),
            BinaryPrimitives.ReadUInt64LittleEndian(wire[24..]));
    }

    public static bool TryParse(ReadOnlySpan<char> displayHex, out TxId id)
    {
        id = default;
        Span<byte> display = stackalloc byte[Size];
        if (!TryDecodeHex(displayHex, display))
            return false;

        Span<byte> wire = stackalloc byte[Size];
        for (int i = 0; i < Size; i++)
            wire[i] = display[Size - 1 - i];
        id = FromWire(wire);
        return true;
    }

    public static TxId Parse(ReadOnlySpan<char> displayHex)
    {
        if (!TryParse(displayHex, out TxId id))
            throw new FormatException("Transaction id must be 64 hexadecimal characters.");
        return id;
    }

    public void WriteWire(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));
        BinaryPrimitives.WriteUInt64LittleEndian(destination, _w0);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[8..], _w1);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[16..], _w2);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[24..], _w3);
    }

    public byte[] ToWire()
    {
        var wire = new byte[Size];
        WriteWire(wire);
        return wire;
    }

    public override string ToString()
    {
        Span<byte> wire = stackalloc byte[Size];
        WriteWire(wire);
        Span<char> chars = stackalloc char[Size * 2];
        for (int i = 0; i < Size; i++)
            wire[Size - 1 - i].TryFormat(chars[(i * 2)..], out _, "x2");
        return new string(chars);
    }

    private static bool TryDecodeHex(ReadOnlySpan<char> text, Span<byte> destination)
    {
        if (text.Length != destination.Length * 2)
            return false;
        for (int i = 0; i < destination.Length; i++)
        {
            if (!byte.TryParse(text.Slice(i * 2, 2), NumberStyles.AllowHexSpecifier, CultureInfo.InvariantCulture, out destination[i]))
                return false;
        }

        return true;
    }
}

/// <summary>交易输入引用的前序输出。</summary>
public readonly record struct OutPoint
{
    public const uint CoinbaseIndex = 0xFFFF_FFFF;

    public TxId TxId { get; }

    public uint Index { get; }

    public OutPoint(TxId txId, uint index)
    {
        TxId = txId;
        Index = index;
    }

    public bool IsCoinbase => Index == CoinbaseIndex && TxId.Equals(default);

    public const int Size = TxId.Size + 4;

    public void Write(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));
        TxId.WriteWire(destination);
        BinaryPrimitives.WriteUInt32LittleEndian(destination[TxId.Size..], Index);
    }
}
