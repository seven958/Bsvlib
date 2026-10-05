namespace Bsvlib.P2P;

public abstract class NetworkMessage
{
    public abstract string Command { get; }

    public abstract int GetPayloadLength();

    public abstract void WritePayload(Span<byte> destination);

    public static bool TryParse(string command, ReadOnlySpan<byte> payload, out NetworkMessage? message)
    {
        message = command switch
        {
            "version" => VersionMessage.TryRead(payload),
            "verack" => VerAckMessage.TryRead(payload),
            "ping" => PingMessage.TryRead(payload),
            "pong" => PongMessage.TryRead(payload),
            "inv" => InvMessage.TryRead(payload),
            "getdata" => GetDataMessage.TryRead(payload),
            "getheaders" => GetHeadersMessage.TryRead(payload),
            "headers" => HeadersMessage.TryRead(payload),
            "tx" => TxMessage.TryRead(payload),
            "block" => BlockMessage.TryRead(payload),
            "getaddr" => GetAddrMessage.TryRead(payload),
            "addr" => AddrMessage.TryRead(payload),
            _ => null,
        };
        if (message is not null)
            return true;
        return !IsKnown(command);
    }

    public static bool IsKnown(string command) => command is "version" or "verack" or "ping" or "pong" or "inv" or "getdata" or "getheaders" or "headers" or "tx" or "block" or "getaddr" or "addr";
}

public sealed class UnknownMessage : NetworkMessage
{
    private readonly byte[] _payload;

    public UnknownMessage(string command, ReadOnlySpan<byte> payload)
    {
        Command = command;
        _payload = payload.ToArray();
    }

    public override string Command { get; }

    public ReadOnlyMemory<byte> Payload => _payload;

    public override int GetPayloadLength() => _payload.Length;

    public override void WritePayload(Span<byte> destination) => _payload.CopyTo(destination);
}
