using Bsvlib.Core;

namespace Bsvlib.P2P;

public sealed class GetAddrMessage : NetworkMessage
{
    public static GetAddrMessage Instance { get; } = new();

    private GetAddrMessage()
    {
    }

    public override string Command => "getaddr";

    public override int GetPayloadLength() => 0;

    public override void WritePayload(Span<byte> destination)
    {
    }

    public static GetAddrMessage? TryRead(ReadOnlySpan<byte> payload) => payload.IsEmpty ? Instance : null;
}

public sealed class AddrMessage : NetworkMessage
{
    public const int MaxCount = 1000;

    private readonly PeerAddress[] _addresses;

    public AddrMessage(IReadOnlyList<PeerAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        if (addresses.Count > MaxCount)
            throw new ArgumentException($"An addr message carries at most {MaxCount} addresses.", nameof(addresses));
        _addresses = addresses.ToArray();
    }

    public override string Command => "addr";

    public IReadOnlyList<PeerAddress> Addresses => _addresses;

    public override int GetPayloadLength() => VarInt.GetSize((ulong)_addresses.Length) + _addresses.Length * PeerAddress.Size;

    public override void WritePayload(Span<byte> destination)
    {
        int offset = VarInt.Write(destination, (ulong)_addresses.Length);
        foreach (PeerAddress address in _addresses)
            offset += address.Write(destination[offset..]);
    }

    public static AddrMessage? TryRead(ReadOnlySpan<byte> payload)
    {
        if (!VarInt.TryRead(payload, out ulong count, out int offset) || count > MaxCount)
            return null;
        var addresses = new PeerAddress[count];
        for (ulong i = 0; i < count; i++)
        {
            if (!PeerAddress.TryRead(payload[offset..], out PeerAddress? address))
                return null;
            addresses[i] = address!;
            offset += PeerAddress.Size;
        }

        return offset == payload.Length ? new AddrMessage(addresses) : null;
    }
}
