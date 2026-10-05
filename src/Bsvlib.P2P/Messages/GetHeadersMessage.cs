using System.Buffers.Binary;
using Bsvlib.Core;

namespace Bsvlib.P2P;

public sealed class GetHeadersMessage : NetworkMessage
{
    private readonly TxId[] _locators;

    public GetHeadersMessage(int protocolVersion, IReadOnlyList<TxId> locators, TxId stopHash)
    {
        ArgumentNullException.ThrowIfNull(locators);
        if (locators.Count > 2000)
            throw new ArgumentException("Locator has more than 2000 hashes.", nameof(locators));
        ProtocolVersion = protocolVersion;
        _locators = locators.ToArray();
        StopHash = stopHash;
    }

    public override string Command => "getheaders";

    public int ProtocolVersion { get; }

    public IReadOnlyList<TxId> Locators => _locators;

    public TxId StopHash { get; }

    public override int GetPayloadLength() => 4 + VarInt.GetSize((ulong)_locators.Length) + _locators.Length * TxId.Size + TxId.Size;

    public override void WritePayload(Span<byte> destination)
    {
        BinaryPrimitives.WriteInt32LittleEndian(destination, ProtocolVersion);
        int offset = 4 + VarInt.Write(destination[4..], (ulong)_locators.Length);
        foreach (TxId hash in _locators)
        {
            hash.WriteWire(destination[offset..]);
            offset += TxId.Size;
        }

        StopHash.WriteWire(destination[offset..]);
    }

    public static GetHeadersMessage? TryRead(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 4 + 1 + TxId.Size || !VarInt.TryRead(payload[4..], out ulong count, out int countSize) || count > 2000)
            return null;
        int offset = 4 + countSize;
        if (payload.Length != offset + (int)count * TxId.Size + TxId.Size)
            return null;
        var locators = new TxId[count];
        for (int i = 0; i < locators.Length; i++)
        {
            locators[i] = TxId.FromWire(payload.Slice(offset, TxId.Size));
            offset += TxId.Size;
        }

        return new GetHeadersMessage(BinaryPrimitives.ReadInt32LittleEndian(payload), locators, TxId.FromWire(payload[offset..]));
    }
}
