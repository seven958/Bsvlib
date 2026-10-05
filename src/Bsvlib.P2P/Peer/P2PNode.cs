using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using Bsvlib.Core;

namespace Bsvlib.P2P;

/// <summary>
/// 本机这一侧。先解析 DNS 种子得到地址并拨号，握成 <see cref="Peer"/> 后再用 addr 消息补充地址池。
/// </summary>
public sealed class P2PNode : IAsyncDisposable
{
    private readonly ISeedResolver _resolver;
    private readonly List<PeerAddress> _addresses = [];
    private readonly List<Connection> _peers = [];
    private readonly object _gate = new();

    public P2PNode(Network network, P2POptions options, ISeedResolver? resolver = null, MessageDispatcher? dispatcher = null)
    {
        Network = network ?? throw new ArgumentNullException(nameof(network));
        Options = options ?? throw new ArgumentNullException(nameof(options));
        _resolver = resolver ?? new DnsSeedResolver();
        Dispatcher = dispatcher ?? new MessageDispatcher();
        Dispatcher.Register(new AddrHandler(this));
        Seeds = NetworkSeeds.For(network);
    }

    public Network Network { get; }

    public P2POptions Options { get; }

    public MessageDispatcher Dispatcher { get; }

    public IReadOnlyList<DnsSeed> Seeds { get; }

    public IReadOnlyList<PeerAddress> Addresses
    {
        get
        {
            lock (_gate)
                return _addresses.ToArray();
        }
    }

    public IReadOnlyList<Peer> Peers
    {
        get
        {
            lock (_gate)
                return _peers.Select(connection => connection.Peer).ToArray();
        }
    }

    public void AddAddresses(IEnumerable<PeerAddress> addresses)
    {
        ArgumentNullException.ThrowIfNull(addresses);
        lock (_gate)
        {
            foreach (PeerAddress address in addresses)
            {
                if (_addresses.All(existing => !existing.EndPoint.Equals(address.EndPoint)))
                    _addresses.Add(address);
            }
        }
    }

    public async Task<IReadOnlyList<PeerAddress>> DiscoverAsync(ulong requiredServices = NetworkSeeds.NodeNetwork, CancellationToken cancellationToken = default)
    {
        var found = new List<PeerAddress>();
        ushort port = checked((ushort)Network.DefaultPort);
        foreach (DnsSeed seed in Seeds)
        {
            IReadOnlyList<PeerAddress> resolved = await _resolver.ResolveAsync(seed, port, requiredServices, cancellationToken).ConfigureAwait(false);
            found.AddRange(resolved);
        }

        AddAddresses(found);
        return Addresses;
    }

    public async Task<Peer> ConnectAsync(PeerAddress address, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(address);
        var client = new TcpClient();
        try
        {
            await client.ConnectAsync(address.EndPoint, cancellationToken).ConfigureAwait(false);
            var peer = new Peer(client.GetStream(), Network, address.EndPoint, Dispatcher);
            await peer.HandshakeAsync(CreateVersion(client, address), cancellationToken).ConfigureAwait(false);
            await peer.SendAsync(GetAddrMessage.Instance, cancellationToken).ConfigureAwait(false);
            lock (_gate)
                _peers.Add(new Connection(peer, client));
            return peer;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public async ValueTask DisposeAsync()
    {
        Connection[] peers;
        lock (_gate)
        {
            peers = _peers.ToArray();
            _peers.Clear();
        }

        foreach (Connection connection in peers)
        {
            await connection.Peer.DisposeAsync().ConfigureAwait(false);
            connection.Client.Dispose();
        }
    }

    private VersionMessage CreateVersion(TcpClient client, PeerAddress remote)
    {
        if (client.Client.LocalEndPoint is not IPEndPoint local)
            throw new InvalidOperationException("Connected socket has no local endpoint.");
        Span<byte> nonceBytes = stackalloc byte[8];
        RandomNumberGenerator.Fill(nonceBytes);
        return new VersionMessage(
            VersionMessage.ProtocolVersion,
            Options.Services,
            DateTimeOffset.UtcNow.ToUnixTimeSeconds(),
            remote.EndPoint.Address,
            (ushort)remote.EndPoint.Port,
            local.Address,
            (ushort)local.Port,
            System.Buffers.Binary.BinaryPrimitives.ReadUInt64LittleEndian(nonceBytes),
            Options.UserAgent,
            Options.StartHeight,
            Options.Relay);
    }

    private sealed record Connection(Peer Peer, TcpClient Client);

    private sealed class AddrHandler : IMessageHandler<AddrMessage>
    {
        private readonly P2PNode _node;

        public AddrHandler(P2PNode node) => _node = node;

        public ValueTask HandleAsync(Peer peer, AddrMessage message, CancellationToken cancellationToken)
        {
            _node.AddAddresses(message.Addresses);
            return ValueTask.CompletedTask;
        }
    }
}
