using System.Net;
using System.Text;
using Bsvlib.Vendors;
using Bsvlib.Core;
using Xunit;

namespace Bsvlib.Vendors.Tests;

public class ClientTests
{
    private const string TxIdText = "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b";

    [Fact]
    public async Task Arc_posts_raw_tx_and_maps_status()
    {
        var handler = new RecordingHandler(_ => Json("""{"txid":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","txStatus":"SEEN_ON_NETWORK","extraInfo":""}"""));
        var client = new ArcClient(new HttpClient(handler) { BaseAddress = ArcClient.GorillaPool }, apiKey: "secret");
        Transaction tx = Sample();

        BroadcastReceipt receipt = await client.BroadcastAsync(tx);

        Assert.Equal(HttpMethod.Post, handler.Method);
        Assert.Equal("https://arc.gorillapool.io/v1/tx", handler.Uri!.ToString());
        Assert.Equal("secret", handler.Authorization);
        Assert.Contains("\"rawTx\":", handler.Body);
        Assert.Equal(BroadcastState.Seen, receipt.State);
        Assert.Equal(TxId.Parse(TxIdText), receipt.TxId);
    }

    [Fact]
    public async Task Arc_status_maps_mined_and_rejected()
    {
        BroadcastReceipt mined = await Status("""{"txid":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","txStatus":"MINED"}""");
        BroadcastReceipt rejected = await Status("""{"txid":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","txStatus":"REJECTED"}""");
        Assert.Equal(BroadcastState.Mined, mined.State);
        Assert.Equal(BroadcastState.Rejected, rejected.State);
    }

    private static async Task<BroadcastReceipt> Status(string json)
    {
        var handler = new RecordingHandler(_ => Json(json));
        var client = new ArcClient(new HttpClient(handler) { BaseAddress = ArcClient.Taal });
        return await client.GetStatusAsync(TxId.Parse(TxIdText));
    }

    [Fact]
    public async Task WhatsOnChain_posts_txhex_and_reads_unspent()
    {
        var handler = new RecordingHandler(request =>
        {
            if (request.RequestUri!.AbsolutePath.EndsWith("/tx/raw", StringComparison.Ordinal))
                return Text("\"" + TxIdText + "\"");
            return Json("""[{"height":10,"tx_pos":1,"tx_hash":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","value":900}]""");
        });
        var client = new WhatsOnChainClient(new HttpClient(handler) { BaseAddress = WhatsOnChainClient.BaseAddress(Network.Mainnet) }, Network.Mainnet);

        BroadcastReceipt receipt = await client.BroadcastAsync(Sample());
        string broadcastBody = handler.Body;
        IReadOnlyList<UnspentOutput> unspent = await client.GetUnspentAsync(Address.P2pkh(new byte[20], Network.Mainnet));

        Assert.Contains("\"txhex\":", broadcastBody);
        Assert.Equal(BroadcastState.Pending, receipt.State);
        Assert.Equal(TxId.Parse(TxIdText), unspent[0].TxId);
        Assert.Equal(1u, unspent[0].Index);
        Assert.Equal(900, unspent[0].Value.Value);
    }

    [Fact]
    public async Task WhatsOnChain_status_uses_confirmations()
    {
        var handler = new RecordingHandler(_ => Json("""{"txid":"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b","confirmations":3,"blockhash":"000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"}"""));
        var client = new WhatsOnChainClient(new HttpClient(handler) { BaseAddress = WhatsOnChainClient.BaseAddress(Network.Testnet) }, Network.Testnet);

        BroadcastReceipt receipt = await client.GetStatusAsync(TxId.Parse(TxIdText));

        Assert.Equal("https://api.whatsonchain.com/v1/bsv/test/tx/hash/" + TxIdText, handler.Uri!.ToString());
        Assert.Equal(BroadcastState.Mined, receipt.State);
        Assert.Throws<ArgumentException>(() => new WhatsOnChainClient(new HttpClient(), Network.ScalingTestnet));
    }

    [Fact]
    public void PayChange_leaves_a_fee_equal_to_the_estimated_signed_size()
    {
        Script locking = Script.P2pkhLock(new byte[20]);
        Script change = Script.P2pkhLock(Enumerable.Repeat((byte)2, 20).ToArray());
        Transaction tx = new TransactionBuilder()
            .AddInput(new OutPoint(TxId.Parse(TxIdText), 0), new Satoshis(100_000), locking)
            .PayChange(change, satoshisPerByte: 1)
            .Build();

        long changeValue = tx.Outputs[0].Value.Value;
        int estimated = tx.GetSerializedLength() + 108;
        Assert.Equal(estimated, 100_000 - changeValue);
        Assert.Equal(change, tx.Outputs[0].LockingScript);
    }

    private static Transaction Sample() => new(1, [], [], 0);

    private static HttpContent Json(string json) => new StringContent(json, Encoding.UTF8, "application/json");

    private static HttpContent Text(string text) => new StringContent(text, Encoding.UTF8, "text/plain");

    private sealed class RecordingHandler : HttpMessageHandler
    {
        private readonly Func<HttpRequestMessage, HttpContent> _content;

        public RecordingHandler(Func<HttpRequestMessage, HttpContent> content) => _content = content;

        public HttpMethod? Method { get; private set; }

        public Uri? Uri { get; private set; }

        public string? Authorization { get; private set; }

        public string Body { get; private set; } = "";

        protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
        {
            Method = request.Method;
            Uri = request.RequestUri;
            Authorization = request.Headers.TryGetValues("Authorization", out IEnumerable<string>? values) ? values.Single() : null;
            Body = request.Content is null ? "" : await request.Content.ReadAsStringAsync(cancellationToken);
            return new HttpResponseMessage(HttpStatusCode.OK) { Content = _content(request) };
        }
    }
}
