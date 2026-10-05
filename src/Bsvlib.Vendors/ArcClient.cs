using System.Text;
using System.Text.Json;
using Bsvlib.Core;

namespace Bsvlib.Vendors;

/// <summary>
/// ARC 客户端。适用于任何 ARC 接入点。<see cref="HttpClient.BaseAddress"/> 设为服务根地址，例如 https://arc.gorillapool.io/ 。
/// </summary>
public sealed class ArcClient : ITransactionBroadcaster
{
    public static Uri GorillaPool { get; } = new("https://arc.gorillapool.io/");

    public static Uri Taal { get; } = new("https://arc.taal.com/");

    private readonly HttpClient _http;
    private readonly string? _apiKey;

    public ArcClient(HttpClient http, string? apiKey = null)
    {
        _http = http ?? throw new ArgumentNullException(nameof(http));
        _apiKey = string.IsNullOrEmpty(apiKey) ? null : apiKey;
    }

    public async Task<BroadcastReceipt> BroadcastAsync(Transaction transaction, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(transaction);
        using var request = new HttpRequestMessage(HttpMethod.Post, "v1/tx")
        {
            Content = new StringContent(JsonSerializer.Serialize(new { rawTx = Hex(transaction) }), Encoding.UTF8, "application/json"),
        };
        AddKey(request);
        return await ReadReceiptAsync(request, cancellationToken).ConfigureAwait(false);
    }

    public async Task<BroadcastReceipt> GetStatusAsync(TxId txId, CancellationToken cancellationToken = default)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "v1/tx/" + txId);
        AddKey(request);
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
            return new BroadcastReceipt(txId, BroadcastState.Unknown, "NOT_FOUND", body);
        if (!response.IsSuccessStatusCode)
            throw new BroadcastException((int)response.StatusCode, body);
        return Parse(body, txId);
    }

    private async Task<BroadcastReceipt> ReadReceiptAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        using HttpResponseMessage response = await _http.SendAsync(request, cancellationToken).ConfigureAwait(false);
        string body = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new BroadcastException((int)response.StatusCode, body);
        return Parse(body, fallback: null);
    }

    private void AddKey(HttpRequestMessage request)
    {
        if (_apiKey is not null)
            request.Headers.TryAddWithoutValidation("Authorization", _apiKey);
    }

    internal static BroadcastReceipt Parse(string json, TxId? fallback)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        JsonElement root = document.RootElement;
        string status = ReadString(root, "txStatus") ?? "";
        string? txidText = ReadString(root, "txid");
        TxId txId = txidText is null ? fallback ?? throw new FormatException("ARC response has no txid.") : TxId.Parse(txidText);
        return new BroadcastReceipt(txId, Map(status), status, ReadString(root, "extraInfo"));
    }

    internal static BroadcastState Map(string status)
    {
        if (status.Contains("REJECT", StringComparison.OrdinalIgnoreCase))
            return BroadcastState.Rejected;
        return status switch
        {
            "MINED" or "CONFIRMED" => BroadcastState.Mined,
            "SEEN_ON_NETWORK" or "ACCEPTED_BY_NETWORK" => BroadcastState.Seen,
            "QUEUED" or "RECEIVED" or "STORED" or "ANNOUNCED_TO_NETWORK" or "REQUESTED_BY_NETWORK" or "SENT_TO_NETWORK" => BroadcastState.Pending,
            _ => BroadcastState.Unknown,
        };
    }

    private static string? ReadString(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    private static string Hex(Transaction transaction) => Convert.ToHexString(transaction.ToBytes()).ToLowerInvariant();
}

public sealed class BroadcastException : Exception
{
    public BroadcastException(int statusCode, string responseBody)
        : base($"Broadcast service returned HTTP {statusCode}.")
    {
        StatusCode = statusCode;
        ResponseBody = responseBody;
    }

    public int StatusCode { get; }

    public string ResponseBody { get; }
}
