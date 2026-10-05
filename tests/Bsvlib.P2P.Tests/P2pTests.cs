using System.Buffers;
using System.IO.Pipelines;
using System.Net;
using Bsvlib.Core;
using Bsvlib.P2P;
using Xunit;

namespace Bsvlib.P2P.Tests;

public class P2pTests
{
    [Fact]
    public void Verack_header_uses_the_empty_payload_checksum()
    {
        Span<byte> header = stackalloc byte[MessageHeader.Size];
        MessageHeader.Write(header, Network.Mainnet, "verack", []);
        Assert.True(MessageHeader.TryRead(header, Network.Mainnet, out MessageHeader parsed));
        Assert.Equal("verack", parsed.Command);
        Assert.Equal(0, parsed.Length);
        Assert.Equal(0xE2E0F65Du, parsed.Checksum);
        Assert.False(MessageHeader.TryRead(header, Network.Testnet, out _));
    }

    [Fact]
    public async Task Version_ping_and_tx_round_trip_on_a_stream()
    {
        var version = new VersionMessage(VersionMessage.ProtocolVersion, 1, 1_700_000_000, IPAddress.Loopback, 8333, IPAddress.Loopback, 18444, 99, "/Bsvlib:0.1.0/", 800_000);
        var ping = new PingMessage(42);
        var tx = new TxMessage(new Transaction(1, [], [], 0));
        await using var stream = new MemoryStream();
        var session = new PeerSession(stream, Network.Regtest);
        await session.WriteAsync(version);
        await session.WriteAsync(ping);
        await session.WriteAsync(tx);
        stream.Position = 0;

        var readVersion = Assert.IsType<VersionMessage>(await session.ReadAsync());
        Assert.Equal(99UL, readVersion.Nonce);
        Assert.Equal("/Bsvlib:0.1.0/", readVersion.UserAgent);
        Assert.Equal(8333, readVersion.ReceiverPort);
        Assert.Equal(0xFF, readVersion.ReceiverAddress[10]);
        Assert.Equal(127, readVersion.ReceiverAddress[12]);

        Assert.Equal(42UL, Assert.IsType<PingMessage>(await session.ReadAsync()).Nonce);
        Assert.Equal(tx.Transaction.Id, Assert.IsType<TxMessage>(await session.ReadAsync()).Transaction.Id);
    }

    [Fact]
    public async Task Handlers_answer_version_with_verack_and_ping_with_pong()
    {
        (PipeDuplexStream clientStream, PipeDuplexStream serverStream) = PipeDuplexStream.Create();
        var dispatcher = new MessageDispatcher();
        dispatcher.Register(new VersionHandler());
        dispatcher.Register(new PingHandler());
        var client = new Peer(clientStream, Network.Regtest);
        var server = new Peer(serverStream, Network.Regtest, new IPEndPoint(IPAddress.Loopback, 18444), dispatcher);

        Task serverLoop = Task.Run(async () =>
        {
            await server.ReceiveAndDispatchAsync();
            await server.ReceiveAndDispatchAsync();
        });

        await client.SendAsync(new VersionMessage(VersionMessage.ProtocolVersion, 1, 10, IPAddress.Loopback, 18444, IPAddress.Loopback, 18444, 7, "/test/", 1));
        await client.SendAsync(new PingMessage(11));
        Assert.IsType<VerAckMessage>(await client.ReceiveAsync());
        Assert.Equal(11UL, Assert.IsType<PongMessage>(await client.ReceiveAsync()).Nonce);
        await serverLoop;
        Assert.Equal(7UL, server.Nonce);
        Assert.Equal("/test/", server.UserAgent);
        Assert.Equal(18444, server.AdvertisedEndPoint!.Port);
    }

    [Fact]
    public async Task Handshake_records_the_remote_peer()
    {
        (PipeDuplexStream clientStream, PipeDuplexStream serverStream) = PipeDuplexStream.Create();
        var local = new Peer(clientStream, Network.Regtest, new IPEndPoint(IPAddress.Parse("203.0.113.8"), 8333));
        var remote = new Peer(serverStream, Network.Regtest, new IPEndPoint(IPAddress.Loopback, 18444));
        VersionMessage localVersion = Version(1, 8333, "/local/");
        VersionMessage remoteVersion = Version(2, 18444, "/remote/");

        await Task.WhenAll(local.HandshakeAsync(localVersion), remote.HandshakeAsync(remoteVersion));

        Assert.Equal("/remote/", local.UserAgent);
        Assert.Equal(2UL, local.Nonce);
        Assert.Equal(900_000, local.StartHeight);
        Assert.Equal(new IPEndPoint(IPAddress.Parse("203.0.113.8"), 8333), local.RemoteEndPoint);
        Assert.Equal("/local/", remote.UserAgent);
        Assert.Equal(1UL, remote.Nonce);
    }

    [Fact]
    public async Task Block_message_streams_transactions_after_the_header()
    {
        var header = new BlockHeader(1, default, default, 100, 0x1d00ffff, 7);
        Transaction tx = new(1, [], [], 0);
        var block = BlockMessage.TryRead(Payload(header, tx))!;
        await using var stream = new MemoryStream();
        await new PeerSession(stream, Network.Mainnet).WriteAsync(block);
        stream.Position = 0;

        var read = Assert.IsType<BlockMessage>(await new PeerSession(stream, Network.Mainnet).ReadAsync());
        Assert.Equal(header.Nonce, read.Header.Nonce);
        Transaction[] txs = await read.ReadTransactionsAsync().ToArrayAsync();
        Assert.Equal(tx.Id, Assert.Single(txs).Id);
    }

    private static VersionMessage Version(ulong nonce, ushort senderPort, string userAgent) =>
        new(VersionMessage.ProtocolVersion, 1, 20, IPAddress.Loopback, 8333, IPAddress.Parse("198.51.100.4"), senderPort, nonce, userAgent, 900_000);

    private static byte[] Payload(BlockHeader header, Transaction transaction)
    {
        var payload = new byte[BlockHeader.Size + 1 + transaction.GetSerializedLength()];
        header.Write(payload);
        payload[BlockHeader.Size] = 1;
        transaction.Write(payload.AsSpan(BlockHeader.Size + 1));
        return payload;
    }

    private sealed class PipeDuplexStream : Stream
    {
        private readonly PipeReader _reader;
        private readonly PipeWriter _writer;

        private PipeDuplexStream(PipeReader reader, PipeWriter writer)
        {
            _reader = reader;
            _writer = writer;
        }

        public static (PipeDuplexStream Client, PipeDuplexStream Server) Create()
        {
            var clientToServer = new Pipe();
            var serverToClient = new Pipe();
            return (
                new PipeDuplexStream(serverToClient.Reader, clientToServer.Writer),
                new PipeDuplexStream(clientToServer.Reader, serverToClient.Writer));
        }

        public override bool CanRead => true;
        public override bool CanWrite => true;
        public override bool CanSeek => false;
        public override long Length => throw new NotSupportedException();
        public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }

        public override int Read(byte[] buffer, int offset, int count) => ReadAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        {
            while (true)
            {
                ReadResult result = await _reader.ReadAsync(cancellationToken).ConfigureAwait(false);
                if (result.Buffer.Length == 0)
                {
                    _reader.AdvanceTo(result.Buffer.End);
                    if (result.IsCompleted)
                        return 0;
                    continue;
                }

                int taken = (int)Math.Min(buffer.Length, result.Buffer.Length);
                result.Buffer.Slice(0, taken).CopyTo(buffer.Span);
                _reader.AdvanceTo(result.Buffer.GetPosition(taken));
                return taken;
            }
        }

        public override void Write(byte[] buffer, int offset, int count) => WriteAsync(buffer.AsMemory(offset, count)).AsTask().GetAwaiter().GetResult();

        public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        {
            await _writer.WriteAsync(buffer, cancellationToken).ConfigureAwait(false);
            await _writer.FlushAsync(cancellationToken).ConfigureAwait(false);
        }

        public override void Flush() => _writer.FlushAsync().AsTask().GetAwaiter().GetResult();
        public override Task FlushAsync(CancellationToken cancellationToken) => _writer.FlushAsync(cancellationToken).AsTask();
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
    }
}
