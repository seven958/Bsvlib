using Bsvlib.Core;
using Bsvlib.Spv;

namespace Bsvlib.P2P;

/// <summary>向一个已经握上手的节点拉区块头，接到 <see cref="HeaderChain"/> 上。</summary>
public static class HeaderSync
{
    public static async Task<int> PullAsync(Peer peer, HeaderChain chain, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(peer);
        ArgumentNullException.ThrowIfNull(chain);
        int added = 0;
        while (true)
        {
            int height = chain.Height;
            await peer.SendAsync(new GetHeadersMessage(VersionMessage.ProtocolVersion, chain.Locators(), default), cancellationToken).ConfigureAwait(false);
            HeadersMessage headers = await ReadHeadersAsync(peer, cancellationToken).ConfigureAwait(false);
            foreach (BlockHeader header in headers.Headers)
            {
                if (!chain.TryAdd(header))
                    throw new InvalidDataException($"Rejected header {header.Hash}.");
            }

            added += chain.Height - height;
            if (headers.Headers.Count < 2000 || chain.Height == height)
                return added;
        }
    }

    private static async Task<HeadersMessage> ReadHeadersAsync(Peer peer, CancellationToken cancellationToken)
    {
        while (true)
        {
            NetworkMessage message = await peer.ReceiveAndDispatchAsync(cancellationToken).ConfigureAwait(false);
            if (message is HeadersMessage headers)
                return headers;
            if (message is BlockMessage)
                throw new InvalidDataException("Header sync received a block before its transactions were read.");
        }
    }
}
