using System.Buffers.Binary;

namespace Bsvlib.P2P;

public sealed class PingMessage : NetworkMessage
{
    public PingMessage(ulong nonce) => Nonce = nonce;

    public override string Command => "ping";

    public ulong Nonce { get; }

    public override int GetPayloadLength() => 8;

    public override void WritePayload(Span<byte> destination) => BinaryPrimitives.WriteUInt64LittleEndian(destination, Nonce);

    public static PingMessage? TryRead(ReadOnlySpan<byte> payload) =>
        payload.Length == 8 ? new PingMessage(BinaryPrimitives.ReadUInt64LittleEndian(payload)) : null;
}
