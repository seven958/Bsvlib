using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;

namespace Bsvlib.P2P;

/// <summary>
/// 一个可拨号的节点地址。线上格式与 addr 消息里的记录相同：时间、服务位、16 字节 IP、大端端口。
/// </summary>
public sealed record PeerAddress(IPAddress Address, ushort Port, ulong Services = 0, uint Time = 0)
{
    public const int Size = 30;

    public IPEndPoint EndPoint
    {
        get
        {
            IPAddress address = Address.IsIPv4MappedToIPv6 ? Address.MapToIPv4() : Address;
            return new IPEndPoint(address, Port);
        }
    }

    public int Write(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));
        BinaryPrimitives.WriteUInt32LittleEndian(destination, Time);
        BinaryPrimitives.WriteUInt64LittleEndian(destination[4..], Services);
        ToIPv6(Address).CopyTo(destination[12..]);
        BinaryPrimitives.WriteUInt16BigEndian(destination[28..], Port);
        return Size;
    }

    public static bool TryRead(ReadOnlySpan<byte> data, out PeerAddress? address)
    {
        address = null;
        if (data.Length < Size)
            return false;
        uint time = BinaryPrimitives.ReadUInt32LittleEndian(data);
        ulong services = BinaryPrimitives.ReadUInt64LittleEndian(data[4..]);
        var ip = new IPAddress(data.Slice(12, 16));
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        ushort port = BinaryPrimitives.ReadUInt16BigEndian(data[28..]);
        address = new PeerAddress(ip, port, services, time);
        return true;
    }

    internal static byte[] ToIPv6(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetworkV6 && !address.IsIPv4MappedToIPv6)
            return address.GetAddressBytes();
        IPAddress v4 = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        var mapped = new byte[16];
        mapped[10] = 0xFF;
        mapped[11] = 0xFF;
        v4.GetAddressBytes().CopyTo(mapped, 12);
        return mapped;
    }
}
