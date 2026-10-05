using System.Text;
using System.Text.Json;
using Bsvlib.Core;

namespace Bsvlib.Protocols;

/// <summary>BSV-20 转移。v1 用代号，v2 用部署输出的 txid_vout。</summary>
public sealed class Bsv20Transfer
{
    public const string ContentType = Bsv20Json.ContentType;

    public Bsv20Transfer(string amount, string? ticker = null, string? id = null)
    {
        if (!Bsv20Json.IsDigits(amount))
            throw new ArgumentException("Amount must be an unsigned integer.", nameof(amount));
        if ((ticker is null) == (id is null))
            throw new ArgumentException("A transfer identifies the token by ticker or by id.");
        if (ticker is not null && !Bsv20Json.IsTicker(ticker))
            throw new ArgumentException("Ticker must be 4 letters.", nameof(ticker));
        if (id is not null && !TrySplitId(id, out _, out _))
            throw new ArgumentException("Id must be txid_vout.", nameof(id));
        Amount = amount;
        Ticker = ticker;
        Id = id;
    }

    public string? Ticker { get; }

    public string? Id { get; }

    public string Amount { get; }

    public Inscription ToInscription() => new(ContentType, Encoding.UTF8.GetBytes(ToJson()));

    public string ToJson()
    {
        string token = Ticker is null ? $"\"id\":\"{Id}\"" : $"\"tick\":\"{Ticker}\"";
        return $$"""{"p":"{{Bsv20Json.Protocol}}","op":"transfer",{{token}},"amt":"{{Amount}}"}""";
    }

    public static bool TryParse(string json, out Bsv20Transfer? transfer)
    {
        transfer = null;
        if (!Bsv20Json.TryOpen(json, out JsonDocument? document))
            return false;
        using (document)
        {
            JsonElement root = document!.RootElement;
            if (Bsv20Json.Text(root, "op") != "transfer" || !Bsv20Json.IsDigits(Bsv20Json.Text(root, "amt")))
                return false;
            string? tick = Bsv20Json.Text(root, "tick");
            string? id = Bsv20Json.Text(root, "id");
            if ((tick is null) == (id is null))
                return false;
            if (tick is not null && !Bsv20Json.IsTicker(tick))
                return false;
            if (id is not null && !TrySplitId(id, out _, out _))
                return false;
            transfer = new Bsv20Transfer(Bsv20Json.Text(root, "amt")!, tick, id);
            return true;
        }
    }

    public static string FormatId(TxId transaction, int output) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{transaction}_{output}");

    public static bool TrySplitId(string id, out TxId transaction, out int output)
    {
        transaction = default;
        output = 0;
        int split = id.LastIndexOf('_');
        if (split <= 0 || split == id.Length - 1)
            return false;
        return TxId.TryParse(id.AsSpan(0, split), out transaction)
            && int.TryParse(id.AsSpan(split + 1), System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out output)
            && output >= 0;
    }
}
