using Bsvlib.Core;

namespace Bsvlib.P2P;

public sealed class HeadersMessage : NetworkMessage
{
    private readonly BlockHeader[] _headers;

    public HeadersMessage(IReadOnlyList<BlockHeader> headers)
    {
        ArgumentNullException.ThrowIfNull(headers);
        if (headers.Count > 2000)
            throw new ArgumentException("Headers message exceeds 2000 headers.", nameof(headers));
        _headers = headers.ToArray();
    }

    public override string Command => "headers";

    public IReadOnlyList<BlockHeader> Headers => _headers;

    public override int GetPayloadLength() => VarInt.GetSize((ulong)_headers.Length) + _headers.Length * (BlockHeader.Size + 1);

    public override void WritePayload(Span<byte> destination)
    {
        int offset = VarInt.Write(destination, (ulong)_headers.Length);
        foreach (BlockHeader header in _headers)
        {
            header.Write(destination[offset..]);
            offset += BlockHeader.Size;
            destination[offset++] = 0;
        }
    }

    public static HeadersMessage? TryRead(ReadOnlySpan<byte> payload)
    {
        if (!VarInt.TryRead(payload, out ulong count, out int offset) || count > 2000)
            return null;
        if (payload.Length != offset + (int)count * (BlockHeader.Size + 1))
            return null;
        var headers = new BlockHeader[count];
        for (int i = 0; i < headers.Length; i++)
        {
            if (!BlockHeader.TryRead(payload[offset..], out BlockHeader? header) || payload[offset + BlockHeader.Size] != 0)
                return null;
            headers[i] = header!;
            offset += BlockHeader.Size + 1;
        }

        return new HeadersMessage(headers);
    }
}
