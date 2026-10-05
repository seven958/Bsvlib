using System.Text;
using System.Text.Json;

namespace Bsvlib.Protocols;

/// <summary>BSV-20 铸造。amt 不能超过该代号 deploy 里的 lim。</summary>
public sealed class Bsv20Mint
{
    public const string ContentType = Bsv20Json.ContentType;

    public Bsv20Mint(string ticker, string amount)
    {
        if (!Bsv20Json.IsTicker(ticker))
            throw new ArgumentException("Ticker must be 4 letters.", nameof(ticker));
        if (!Bsv20Json.IsDigits(amount))
            throw new ArgumentException("Amount must be an unsigned integer.", nameof(amount));
        Ticker = ticker;
        Amount = amount;
    }

    public string Ticker { get; }

    public string Amount { get; }

    public Inscription ToInscription() => new(ContentType, Encoding.UTF8.GetBytes(ToJson()));

    public string ToJson() =>
        $$"""{"p":"{{Bsv20Json.Protocol}}","op":"mint","tick":"{{Ticker}}","amt":"{{Amount}}"}""";

    public static bool TryParse(string json, out Bsv20Mint? mint)
    {
        mint = null;
        if (!Bsv20Json.TryOpen(json, out JsonDocument? document))
            return false;
        using (document)
        {
            JsonElement root = document!.RootElement;
            string? tick = Bsv20Json.Text(root, "tick");
            string? amt = Bsv20Json.Text(root, "amt");
            if (Bsv20Json.Text(root, "op") != "mint" || !Bsv20Json.IsTicker(tick) || !Bsv20Json.IsDigits(amt))
                return false;
            mint = new Bsv20Mint(tick!, amt!);
            return true;
        }
    }
}
