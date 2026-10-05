using System.Net;
using System.Net.Sockets;
using Bsvlib.Core;
using Bsvlib.P2P;
using Xunit;

namespace Bsvlib.P2P.Tests;

public class DiscoveryTests
{
    [Fact]
    public void Service_bit_query_precedes_the_bare_seed_host()
    {
        string[] queries = new DnsSeed("seed.bitcoinsv.io", true).Queries(NetworkSeeds.NodeNetwork).ToArray();
        Assert.Equal(["x1.seed.bitcoinsv.io", "seed.bitcoinsv.io"], queries);
        Assert.Equal(3, NetworkSeeds.For(Network.Mainnet).Count);
        Assert.Empty(NetworkSeeds.For(Network.Regtest));
    }

    [Fact]
    public void Addr_message_round_trips_a_peer_address()
    {
        var message = new AddrMessage([new PeerAddress(IPAddress.Parse("198.51.100.4"), 8333, NetworkSeeds.NodeNetwork, 100)]);
        var payload = new byte[message.GetPayloadLength()];
        message.WritePayload(payload);
        AddrMessage read = AddrMessage.TryRead(payload)!;
        Assert.Equal(IPAddress.Parse("198.51.100.4"), Assert.Single(read.Addresses).Address);
        Assert.Equal(8333, read.Addresses[0].Port);
    }

    [Fact]
    public async Task Discover_fills_the_address_book_from_seeds()
    {
        var node = new P2PNode(Network.Mainnet, new P2POptions("/Bsvlib:0.1.0/"), new FakeResolver());
        IReadOnlyList<PeerAddress> addresses = await node.DiscoverAsync();
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.8"), Network.Mainnet.DefaultPort), Assert.Single(addresses).EndPoint);
    }

    [Fact]
    public async Task Node_connects_an_address_then_stores_addresses_from_the_peer()
    {
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        var node = new P2PNode(Network.Regtest, new P2POptions("/local/") { StartHeight = 42 });
        var remoteVersion = Version(2, "/remote/");
        VersionMessage? announced = null;
        Task remote = Task.Run(async () =>
        {
            using TcpClient accepted = await listener.AcceptTcpClientAsync();
            await using var peer = new Peer(accepted.GetStream(), Network.Regtest);
            await peer.HandshakeAsync(remoteVersion);
            announced = peer.RemoteVersion;
            Assert.IsType<GetAddrMessage>(await peer.ReceiveAsync());
            await peer.SendAsync(new AddrMessage([new PeerAddress(IPAddress.Parse("203.0.113.9"), 8333)]));
        });

        var address = new PeerAddress(((IPEndPoint)listener.LocalEndpoint).Address, (ushort)((IPEndPoint)listener.LocalEndpoint).Port);
        Peer local = await node.ConnectAsync(address);
        Assert.Equal("/remote/", local.UserAgent);
        await local.ReceiveAndDispatchAsync();
        await remote;
        Assert.Contains(node.Addresses, candidate => candidate.EndPoint.Equals(new IPEndPoint(IPAddress.Parse("203.0.113.9"), 8333)));
        Assert.Equal("/local/", announced!.UserAgent);
        Assert.Equal(42, announced.StartHeight);
        Assert.Equal(VersionMessage.ProtocolVersion, announced.Version);
        Assert.Equal(address.Port, announced.ReceiverPort);
        await node.DisposeAsync();
    }

    private static VersionMessage Version(ulong nonce, string userAgent) =>
        new(VersionMessage.ProtocolVersion, NetworkSeeds.NodeNetwork, 20, IPAddress.Loopback, 8333, IPAddress.Loopback, 8333, nonce, userAgent, 1);

    private sealed class FakeResolver : ISeedResolver
    {
        public Task<IReadOnlyList<PeerAddress>> ResolveAsync(DnsSeed seed, ushort port, ulong requiredServices, CancellationToken cancellationToken) =>
            Task.FromResult<IReadOnlyList<PeerAddress>>([new PeerAddress(IPAddress.Parse("203.0.113.8"), port, requiredServices)]);
    }
}
