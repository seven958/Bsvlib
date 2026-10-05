using System.Net;
using System.Net.Sockets;
using Bsvlib.Core;

namespace Bsvlib.P2P;

/// <summary>DNS 种子。支持服务位过滤时，先查询 x{services:x}.host，没有结果再查主机名本身。</summary>
public sealed record DnsSeed(string Host, bool SupportsServiceBits)
{
    public IEnumerable<string> Queries(ulong requiredServices)
    {
        if (SupportsServiceBits && requiredServices != 0)
            yield return FormattableString.Invariant($"x{requiredServices:x}.{Host}");
        yield return Host;
    }
}

public static class NetworkSeeds
{
    public const ulong NodeNetwork = 1;

    private static readonly DnsSeed[] Mainnet =
    [
        new("seed.bitcoinsv.io", true),
        new("seed.satoshisvision.network", true),
        new("seed.bitcoinseed.directory", true),
    ];

    private static readonly DnsSeed[] Testnet =
    [
        new("testnet-seed.bitcoinsv.io", true),
        new("testnet-seed.bitcoincloud.net", true),
        new("testnet-seed.bitcoinseed.directory", true),
    ];

    private static readonly DnsSeed[] ScalingTestnet =
    [
        new("stn-seed.bitcoinsv.io", true),
        new("stn-seed.bitcoinseed.directory", true),
    ];

    public static IReadOnlyList<DnsSeed> For(Network network)
    {
        ArgumentNullException.ThrowIfNull(network);
        if (ReferenceEquals(network, Network.Mainnet))
            return Mainnet;
        if (ReferenceEquals(network, Network.Testnet))
            return Testnet;
        if (ReferenceEquals(network, Network.ScalingTestnet))
            return ScalingTestnet;
        return [];
    }
}

public interface ISeedResolver
{
    Task<IReadOnlyList<PeerAddress>> ResolveAsync(DnsSeed seed, ushort port, ulong requiredServices, CancellationToken cancellationToken);
}

public sealed class DnsSeedResolver : ISeedResolver
{
    public async Task<IReadOnlyList<PeerAddress>> ResolveAsync(DnsSeed seed, ushort port, ulong requiredServices, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(seed);
        uint seen = (uint)DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        foreach (string query in seed.Queries(requiredServices))
        {
            IPAddress[] ips;
            try
            {
                ips = await Dns.GetHostAddressesAsync(query, cancellationToken).ConfigureAwait(false);
            }
            catch (SocketException)
            {
                continue;
            }

            PeerAddress[] found = ips
                .Where(ip => ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6)
                .Select(ip => new PeerAddress(ip.IsIPv4MappedToIPv6 ? ip.MapToIPv4() : ip, port, requiredServices, seen))
                .DistinctBy(address => address.EndPoint)
                .ToArray();
            if (found.Length > 0)
                return found;
        }

        return [];
    }
}
