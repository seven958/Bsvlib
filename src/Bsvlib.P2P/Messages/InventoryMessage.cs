using System.Buffers.Binary;
using Bsvlib.Core;

namespace Bsvlib.P2P;

public enum InventoryType : uint
{
    Error = 0,
    Transaction = 1,
    Block = 2,
    FilteredBlock = 3,
    CompactBlock = 4,
}

public readonly record struct InventoryVector(InventoryType Type, TxId Hash)
{
    public const int Size = 36;

    public void Write(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt32LittleEndian(destination, (uint)Type);
        Hash.WriteWire(destination[4..]);
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out InventoryVector vector)
    {
        vector = default;
        if (data.Length < Size)
            return false;
        vector = new InventoryVector((InventoryType)BinaryPrimitives.ReadUInt32LittleEndian(data), TxId.FromWire(data.Slice(4, TxId.Size)));
        return true;
    }
}

public abstract class InventoryMessage : NetworkMessage
{
    private readonly InventoryVector[] _items;

    protected InventoryMessage(IReadOnlyList<InventoryVector> items)
    {
        ArgumentNullException.ThrowIfNull(items);
        if (items.Count > 50_000)
            throw new ArgumentException("Inventory exceeds 50000 items.", nameof(items));
        _items = items.ToArray();
    }

    public IReadOnlyList<InventoryVector> Items => _items;

    public override int GetPayloadLength() => VarInt.GetSize((ulong)_items.Length) + _items.Length * InventoryVector.Size;

    public override void WritePayload(Span<byte> destination)
    {
        int offset = VarInt.Write(destination, (ulong)_items.Length);
        foreach (InventoryVector item in _items)
        {
            item.Write(destination[offset..]);
            offset += InventoryVector.Size;
        }
    }

    protected static bool TryReadItems(ReadOnlySpan<byte> payload, out InventoryVector[]? items)
    {
        items = null;
        if (!VarInt.TryRead(payload, out ulong count, out int offset) || count > 50_000)
            return false;
        if (payload.Length != offset + (int)count * InventoryVector.Size)
            return false;
        items = new InventoryVector[count];
        for (int i = 0; i < items.Length; i++)
        {
            if (!InventoryVector.TryRead(payload[offset..], out items[i]))
                return false;
            offset += InventoryVector.Size;
        }

        return true;
    }
}

public sealed class InvMessage : InventoryMessage
{
    public InvMessage(IReadOnlyList<InventoryVector> items) : base(items)
    {
    }

    public override string Command => "inv";

    public static InvMessage? TryRead(ReadOnlySpan<byte> payload) =>
        TryReadItems(payload, out InventoryVector[]? items) ? new InvMessage(items!) : null;
}

public sealed class GetDataMessage : InventoryMessage
{
    public GetDataMessage(IReadOnlyList<InventoryVector> items) : base(items)
    {
    }

    public override string Command => "getdata";

    public static GetDataMessage? TryRead(ReadOnlySpan<byte> payload) =>
        TryReadItems(payload, out InventoryVector[]? items) ? new GetDataMessage(items!) : null;
}
