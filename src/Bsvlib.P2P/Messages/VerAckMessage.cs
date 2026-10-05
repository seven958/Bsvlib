namespace Bsvlib.P2P;

public sealed class VerAckMessage : NetworkMessage
{
    public static VerAckMessage Instance { get; } = new();

    private VerAckMessage()
    {
    }

    public override string Command => "verack";

    public override int GetPayloadLength() => 0;

    public override void WritePayload(Span<byte> destination)
    {
    }

    public static VerAckMessage? TryRead(ReadOnlySpan<byte> payload) => payload.IsEmpty ? Instance : null;
}
