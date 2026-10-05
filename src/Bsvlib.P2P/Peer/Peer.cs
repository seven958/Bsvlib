using System.Net;
using Bsvlib.Core;

namespace Bsvlib.P2P;

/// <summary>
/// 一条连接的另一端。地址来自建连时看到的终结点，身份来自对方发来的 version。
/// </summary>
public sealed class Peer : IAsyncDisposable
{
    private readonly PeerSession _session;
    private readonly MessageDispatcher _dispatcher;

    public Peer(Stream stream, Network network, IPEndPoint? remoteEndPoint = null, MessageDispatcher? dispatcher = null, int maxPayload = PeerSession.DefaultMaxPayload)
    {
        ArgumentNullException.ThrowIfNull(network);
        RemoteEndPoint = remoteEndPoint;
        _session = new PeerSession(stream, network, maxPayload);
        _dispatcher = dispatcher ?? new MessageDispatcher();
        Network = network;
    }

    public Network Network { get; }

    public IPEndPoint? RemoteEndPoint { get; }

    public VersionMessage? RemoteVersion { get; private set; }

    public string? UserAgent => RemoteVersion?.UserAgent;

    public ulong Services => RemoteVersion?.Services ?? 0;

    public int StartHeight => RemoteVersion?.StartHeight ?? 0;

    public ulong Nonce => RemoteVersion?.Nonce ?? 0;

    public IPEndPoint? AdvertisedEndPoint => RemoteVersion is null
        ? null
        : new IPEndPoint(new IPAddress(RemoteVersion.SenderAddress), RemoteVersion.SenderPort);

    public MessageDispatcher Dispatcher => _dispatcher;

    public Task SendAsync(NetworkMessage message, CancellationToken cancellationToken = default) =>
        _session.WriteAsync(message, cancellationToken);

    public async Task<NetworkMessage> ReceiveAsync(CancellationToken cancellationToken = default)
    {
        NetworkMessage message = await _session.ReadAsync(cancellationToken).ConfigureAwait(false);
        Remember(message);
        return message;
    }

    public async Task HandshakeAsync(VersionMessage local, CancellationToken cancellationToken = default)
    {
        RemoteVersion = await _session.HandshakeAsync(local, cancellationToken).ConfigureAwait(false);
    }

    public async Task<NetworkMessage> ReceiveAndDispatchAsync(CancellationToken cancellationToken = default)
    {
        NetworkMessage message = await ReceiveAsync(cancellationToken).ConfigureAwait(false);
        if (message is not BlockMessage)
            await _dispatcher.DispatchAsync(this, message, cancellationToken).ConfigureAwait(false);
        return message;
    }

    public ValueTask DisposeAsync() => _session.DisposeAsync();

    private void Remember(NetworkMessage message)
    {
        if (message is VersionMessage version)
            RemoteVersion = version;
    }
}
