using System.Buffers.Binary;

namespace Bsvlib.P2P;

public sealed class PongMessage : NetworkMessage
{
    public PongMessage(ulong nonce) => Nonce = nonce;

    public override string Command => "pong";

    public ulong Nonce { get; }

    public override int GetPayloadLength() => 8;

    public override void WritePayload(Span<byte> destination) => BinaryPrimitives.WriteUInt64LittleEndian(destination, Nonce);

    public static PongMessage? TryRead(ReadOnlySpan<byte> payload) =>
        payload.Length == 8 ? new PongMessage(BinaryPrimitives.ReadUInt64LittleEndian(payload)) : null;
}
