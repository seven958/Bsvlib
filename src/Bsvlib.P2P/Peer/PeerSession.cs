using Bsvlib.Core;

namespace Bsvlib.P2P;

public sealed class PeerSession : IAsyncDisposable
{
    public const int DefaultMaxPayload = 32 * 1024 * 1024;

    private readonly Stream _stream;
    private readonly Network _network;
    private readonly int _maxPayload;

    public PeerSession(Stream stream, Network network, int maxPayload = DefaultMaxPayload)
    {
        _stream = stream ?? throw new ArgumentNullException(nameof(stream));
        _network = network ?? throw new ArgumentNullException(nameof(network));
        _maxPayload = maxPayload;
    }

    public async Task WriteAsync(NetworkMessage message, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(message);
        var payload = new byte[message.GetPayloadLength()];
        message.WritePayload(payload);
        var frame = new byte[MessageHeader.Size + payload.Length];
        MessageHeader.Write(frame.AsSpan(0, MessageHeader.Size), _network, message.Command, payload);
        payload.CopyTo(frame.AsSpan(MessageHeader.Size));
        await _stream.WriteAsync(frame, cancellationToken).ConfigureAwait(false);
        await _stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<NetworkMessage> ReadAsync(CancellationToken cancellationToken = default)
    {
        var headerBytes = new byte[MessageHeader.Size];
        await StreamBytes.ReadExactlyAsync(_stream, headerBytes, cancellationToken).ConfigureAwait(false);
        if (!MessageHeader.TryRead(headerBytes, _network, out MessageHeader header))
            throw new InvalidDataException("Message header is invalid.");

        if (header.Command == "block")
            return await BlockMessage.ReadStreamingAsync(_stream, header.Length, header.Checksum, cancellationToken).ConfigureAwait(false);

        if (header.Length > _maxPayload)
            throw new InvalidDataException($"Payload of {header.Length} bytes exceeds the limit.");
        var payload = new byte[header.Length];
        if (header.Length > 0)
            await StreamBytes.ReadExactlyAsync(_stream, payload, cancellationToken).ConfigureAwait(false);
        if (!header.Matches(payload))
            throw new InvalidDataException("Message checksum does not match.");
        if (NetworkMessage.TryParse(header.Command, payload, out NetworkMessage? message) && message is not null)
            return message;
        if (message is null && NetworkMessage.IsKnown(header.Command))
            throw new InvalidDataException($"Payload for {header.Command} is invalid.");
        return new UnknownMessage(header.Command, payload);
    }

    public async Task<VersionMessage> HandshakeAsync(VersionMessage local, CancellationToken cancellationToken = default)
    {
        await WriteAsync(local, cancellationToken).ConfigureAwait(false);
        if (await ReadAsync(cancellationToken).ConfigureAwait(false) is not VersionMessage remote)
            throw new InvalidDataException("Peer did not send version.");
        await WriteAsync(VerAckMessage.Instance, cancellationToken).ConfigureAwait(false);
        if (await ReadAsync(cancellationToken).ConfigureAwait(false) is not VerAckMessage)
            throw new InvalidDataException("Peer did not send verack.");
        return remote;
    }

    public ValueTask DisposeAsync() => _stream.DisposeAsync();
}
