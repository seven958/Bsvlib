using System.Buffers.Binary;
using System.Text;
using Bsvlib.Core;
using Bsvlib.Crypto;

namespace Bsvlib.P2P;

public readonly record struct MessageHeader(string Command, int Length, uint Checksum)
{
    public const int Size = 24;

    public static bool TryRead(ReadOnlySpan<byte> data, Network network, out MessageHeader header)
    {
        header = default;
        if (data.Length < Size || !data[..4].SequenceEqual(network.Magic.Span))
            return false;

        int length = BinaryPrimitives.ReadInt32LittleEndian(data[16..]);
        if (length < 0)
            return false;

        string command = Encoding.ASCII.GetString(data.Slice(4, 12)).TrimEnd('\0');
        if (command.Length == 0)
            return false;

        header = new MessageHeader(command, length, BinaryPrimitives.ReadUInt32LittleEndian(data[20..]));
        return true;
    }

    public static void Write(Span<byte> destination, Network network, string command, ReadOnlySpan<byte> payload)
    {
        if (destination.Length < Size)
            throw new ArgumentException("Destination must be at least 24 bytes.", nameof(destination));
        if (payload.Length > int.MaxValue - Size)
            throw new ArgumentException("Payload is too large.", nameof(payload));

        network.Magic.Span.CopyTo(destination);
        WriteCommand(destination[4..], command);
        BinaryPrimitives.WriteInt32LittleEndian(destination[16..], payload.Length);
        Span<byte> hash = stackalloc byte[32];
        Hash256.Write(payload, hash);
        hash[..4].CopyTo(destination[20..]);
    }

    public bool Matches(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != Length)
            return false;
        Span<byte> hash = stackalloc byte[32];
        Hash256.Write(payload, hash);
        return BinaryPrimitives.ReadUInt32LittleEndian(hash) == Checksum;
    }

    private static void WriteCommand(Span<byte> destination, string command)
    {
        destination[..12].Clear();
        if (command.Length is 0 or > 12)
            throw new ArgumentException("Command must be 1 to 12 ASCII characters.", nameof(command));
        int written = Encoding.ASCII.GetBytes(command, destination[..12]);
        if (written != command.Length)
            throw new ArgumentException("Command must be ASCII.", nameof(command));
    }
}
