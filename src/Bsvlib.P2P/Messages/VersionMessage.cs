using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Bsvlib.Core;

namespace Bsvlib.P2P;

public sealed class VersionMessage : NetworkMessage
{
    public const int ProtocolVersion = 70016;

    public VersionMessage(
        int version,
        ulong services,
        long timestamp,
        IPAddress receiverAddress,
        ushort receiverPort,
        IPAddress senderAddress,
        ushort senderPort,
        ulong nonce,
        string userAgent,
        int startHeight,
        bool relay = true)
    {
        Version = version;
        Services = services;
        Timestamp = timestamp;
        ReceiverAddress = ToIPv6(receiverAddress);
        ReceiverPort = receiverPort;
        SenderAddress = ToIPv6(senderAddress);
        SenderPort = senderPort;
        Nonce = nonce;
        UserAgent = userAgent ?? throw new ArgumentNullException(nameof(userAgent));
        StartHeight = startHeight;
        Relay = relay;
    }

    private VersionMessage()
    {
        ReceiverAddress = new byte[16];
        SenderAddress = new byte[16];
        UserAgent = "";
    }

    public override string Command => "version";

    public int Version { get; private init; }

    public ulong Services { get; private init; }

    public long Timestamp { get; private init; }

    public byte[] ReceiverAddress { get; }

    public ushort ReceiverPort { get; private init; }

    public byte[] SenderAddress { get; }

    public ushort SenderPort { get; private init; }

    public ulong Nonce { get; private init; }

    public string UserAgent { get; private init; }

    public int StartHeight { get; private init; }

    public bool Relay { get; private init; }

    public override int GetPayloadLength()
    {
        int agent = Encoding.UTF8.GetByteCount(UserAgent);
        return 86 + VarInt.GetSize((ulong)agent) - 1 + agent;
    }

    public override void WritePayload(Span<byte> destination)
    {
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(destination[offset..], Version);
        offset += 4;
        BinaryPrimitives.WriteUInt64LittleEndian(destination[offset..], Services);
        offset += 8;
        BinaryPrimitives.WriteInt64LittleEndian(destination[offset..], Timestamp);
        offset += 8;
        offset += WriteAddress(destination[offset..], Services, ReceiverAddress, ReceiverPort);
        offset += WriteAddress(destination[offset..], Services, SenderAddress, SenderPort);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[offset..], Nonce);
        offset += 8;
        byte[] agent = Encoding.UTF8.GetBytes(UserAgent);
        offset += VarInt.Write(destination[offset..], (ulong)agent.Length);
        agent.CopyTo(destination[offset..]);
        offset += agent.Length;
        BinaryPrimitives.WriteInt32LittleEndian(destination[offset..], StartHeight);
        destination[offset + 4] = Relay ? (byte)1 : (byte)0;
    }

    public static VersionMessage? TryRead(ReadOnlySpan<byte> payload)
    {
        if (payload.Length < 85)
            return null;
        int offset = 0;
        int version = BinaryPrimitives.ReadInt32LittleEndian(payload[offset..]);
        offset += 4;
        ulong services = BinaryPrimitives.ReadUInt64LittleEndian(payload[offset..]);
        offset += 8;
        long timestamp = BinaryPrimitives.ReadInt64LittleEndian(payload[offset..]);
        offset += 8;
        if (!TryReadAddress(payload, ref offset, out _, out byte[] receiver, out ushort receiverPort))
            return null;
        if (!TryReadAddress(payload, ref offset, out _, out byte[] sender, out ushort senderPort))
            return null;
        if (payload.Length - offset < 8)
            return null;
        ulong nonce = BinaryPrimitives.ReadUInt64LittleEndian(payload[offset..]);
        offset += 8;
        if (!VarInt.TryRead(payload[offset..], out ulong agentLength, out int agentVar))
            return null;
        offset += agentVar;
        if (agentLength > 4000 || payload.Length - offset < (int)agentLength + 4)
            return null;
        string agent = Encoding.UTF8.GetString(payload.Slice(offset, (int)agentLength));
        offset += (int)agentLength;
        int height = BinaryPrimitives.ReadInt32LittleEndian(payload[offset..]);
        offset += 4;
        bool relay = offset >= payload.Length || payload[offset] != 0;
        var message = new VersionMessage
        {
            Version = version,
            Services = services,
            Timestamp = timestamp,
            ReceiverPort = receiverPort,
            SenderPort = senderPort,
            Nonce = nonce,
            UserAgent = agent,
            StartHeight = height,
            Relay = relay,
        };
        receiver.CopyTo(message.ReceiverAddress, 0);
        sender.CopyTo(message.SenderAddress, 0);
        return message;
    }

    private static int WriteAddress(Span<byte> destination, ulong services, ReadOnlySpan<byte> address, ushort port)
    {
        BinaryPrimitives.WriteUInt64LittleEndian(destination, services);
        address.CopyTo(destination[8..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[24..], port);
        return 26;
    }

    private static bool TryReadAddress(ReadOnlySpan<byte> payload, ref int offset, out ulong services, out byte[] address, out ushort port)
    {
        services = 0;
        address = [];
        port = 0;
        if (payload.Length - offset < 26)
            return false;
        services = BinaryPrimitives.ReadUInt64LittleEndian(payload[offset..]);
        address = payload.Slice(offset + 8, 16).ToArray();
        port = BinaryPrimitives.ReadUInt16BigEndian(payload[(offset + 24)..]);
        offset += 26;
        return true;
    }

    private static byte[] ToIPv6(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6)
            return address.GetAddressBytes();
        var mapped = new byte[16];
        mapped[10] = 0xFF;
        mapped[11] = 0xFF;
        address.GetAddressBytes().CopyTo(mapped, 12);
        return mapped;
    }
}
