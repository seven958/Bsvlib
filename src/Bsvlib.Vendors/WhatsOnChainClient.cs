using System.Text;
using System.Text.Json;
using Bsvlib.Core;

namespace Bsvlib.Vendors;

/// <summary>
/// WhatsOnChain 客户端。<see cref="HttpClient.BaseAddress"/> 设为 https://api.whatsonchain.com/v1/bsv/main/ 或 test。
/// 只支持主网和测试网。
/// </summary>
public sealed class WhatsOnChainClient : ITransactionBroadcaster
{
    private readonly HttpClient _http;
    private readonly Network _network;

    public WhatsOnChainClient(HttpClient http, Network network)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _network = network ?? throw new ArgumentNullException(nameof(network));
        if (network != Network.Mainnet && network != Network.Testnet)
            throw new ArgumentException("WhatsOnChain supports mainnet and testnet.", nameof(network));
    }

    public static Uri BaseAddress(Network network) => network == Network.Mainnet
        ? new Uri("https://api.whatsonchain.com/v1/bsv/main/")
        : network == Network.Testnet
            ? new Uri("https://api.whatsonchain.com/v1/bsv/test/")
            : throw new ArgumentException("WhatsOnChain supports mainnet and testnet.", nameof(network));

    public async Task<BroadcastReceipt> BroadcastAsync(Transaction transaction, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        string hex = Convert.ToHexString(transaction.ToBytes()).ToLowerInvariant();
        using var request = new HttpRequestMessage(HttpMethod.Post, "tx/raw")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { txhex = hex }), Encoding.UTF8, "application/json"),
        };
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string body = (await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false)).Trim().Trim('"');
        if (!response.IsSuccessStatusCode)
            throw new BroadcastException((int)response.StatusCode, body);
        return new BroadcastReceipt(TxId.Parse(body), BroadcastState.Pending, "SENT", null);
    }

    public async Task<BroadcastReceipt> GetStatusAsync(TxId txId, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "tx/hash/" + txId);
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return new BroadcastReceipt(txId, BroadcastState.Unknown, "NOT_FOUND", body);
        if (!response.IsSuccessStatusCode)
            throw new BroadcastException((int)response.StatusCode, body);

        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement root = document.RootElement;
        bool mined = false;
        if (root.TryGetProperty("confirmations", out JsonElement confirmations) && confirmations.TryGetInt64(out long count) && count > 0)
            mined = true;
        else if (root.TryGetProperty("blockhash", out JsonElement blockHash) && blockHash.ValueKind == JsonValueKind.String && !string.IsNullOrEmpty(blockHash.GetString()))
            mined = true;
        return new BroadcastReceipt(txId, mined ? BroadcastState.Mined : BroadcastState.Seen, mined ? "MINED" : "SEEN", null);
    }

    public async Task<IReadOnlyList<UnspentOutput>> GetUnspentAsync(Address address, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(address);
        if (address.Network != _network)
            throw new ArgumentException("Address network does not match this client.", nameof(address));

        using var request = new HttpRequestMessage(HttpMethod.Get, "address/" + address + "/unspent");
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new BroadcastException((int)response.StatusCode, body);

        using JsonDocument document = JsonDocument.Parse(body);
        JsonElement array = document.RootElement;
        var outputs = new List<UnspentOutput>(array.GetArrayLength());
        foreach (JsonElement item in array.EnumerateArray())
        {
            outputs.Add(new UnspentOutput(
                TxId.Parse(item.GetProperty("tx_hash").GetString()!),
                item.GetProperty("tx_pos").GetUInt32(),
                new Satoshis(item.GetProperty("value").GetInt64()),
                item.TryGetProperty("height", out JsonElement height) ? height.GetInt64() : 0));
        }

        return outputs;
    }
}

public sealed record UnspentOutput(TxId TxId, uint Index, Satoshis Value, long Height);
