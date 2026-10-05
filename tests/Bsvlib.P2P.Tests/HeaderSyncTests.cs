using System.Net;
using System.Net.Sockets;
using Bsvlib.Core;
using Bsvlib.P2P;
using Bsvlib.Spv;
using Xunit;

namespace Bsvlib.P2P.Tests;

public class HeaderSyncTests
{
    [Fact]
    public async Task Pull_extends_the_local_chain_from_the_peer()
    {
        var remoteChain = new HeaderChain(Network.Regtest);
        Mine(remoteChain, 3);
        using var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        Task remote = Task.Run(async () =>
        {
            using TcpClient accepted = await listener.AcceptTcpClientAsync();
            await using var peer = new Peer(accepted.GetStream(), Network.Regtest);
            var request = Assert.IsType<GetHeadersMessage>(await peer.ReceiveAsync());
            await peer.SendAsync(new HeadersMessage(After(remoteChain, request.Locators)));
        });

        using var client = new TcpClient();
        await client.ConnectAsync((IPEndPoint)listener.LocalEndpoint);
        await using var local = new Peer(client.GetStream(), Network.Regtest);
        var chain = new HeaderChain(Network.Regtest);
        int added = await HeaderSync.PullAsync(local, chain);
        await remote;

        Assert.Equal(3, added);
        Assert.Equal(remoteChain.Tip.Hash, chain.Tip.Hash);
        Assert.True(chain.IsValidRoot(3, remoteChain.GetHeader(3).MerkleRoot));
    }

    private static void Mine(HeaderChain chain, int count)
    {
        for (int i = 0; i < count; i++)
        {
            BlockHeader previous = chain.Tip;
            uint time = previous.Time + 600;
            uint bits = Difficulty.NextBits(Headers(chain), Work(chain), chain.Parameters, time);
            var merkle = TxId.Parse(new string('b', 64));
            bool added = false;
            for (uint nonce = 0; nonce < 64 && !added; nonce++)
            {
                var header = new BlockHeader(1, previous.Hash, merkle, time, bits, nonce);
                if (ProofOfWork.Check(header.Hash, bits, chain.Parameters.PowLimit))
                    added = chain.TryAdd(header);
            }

            Assert.True(added);
        }
    }

    private static List<BlockHeader> Headers(HeaderChain chain)
    {
        var headers = new List<BlockHeader>(chain.Height + 1);
        for (int height = 0; height <= chain.Height; height++)
            headers.Add(chain.GetHeader(height));
        return headers;
    }

    private static List<System.Numerics.BigInteger> Work(HeaderChain chain)
    {
        var work = new List<System.Numerics.BigInteger>(chain.Height + 1);
        System.Numerics.BigInteger sum = System.Numerics.BigInteger.Zero;
        for (int height = 0; height <= chain.Height; height++)
        {
            sum += ProofOfWork.Work(chain.GetHeader(height).Bits);
            work.Add(sum);
        }

        return work;
    }

    private static List<BlockHeader> After(HeaderChain chain, IReadOnlyList<TxId> locators)
    {
        int fork = 0;
        foreach (TxId locator in locators)
        {
            if (chain.TryGetHeight(locator, out int height))
            {
                fork = height;
                break;
            }
        }

        var batch = new List<BlockHeader>();
        for (int height = fork + 1; height <= chain.Height; height++)
            batch.Add(chain.GetHeader(height));
        return batch;
    }
}
