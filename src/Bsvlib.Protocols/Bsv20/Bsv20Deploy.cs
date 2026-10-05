using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Bsvlib.Protocols;

/// <summary>BSV-20 部署。v1 用 4 字符代号和 max；v2 的 deploy+mint 只有 amt。</summary>
public sealed class Bsv20Deploy
{
    public const string ContentType = Bsv20Json.ContentType;

    public Bsv20Deploy(string maxSupply, string? ticker = null, string? mintLimit = null, int? decimals = null)
    {
        if (!Bsv20Json.IsDigits(maxSupply))
            throw new ArgumentException("Supply must be an unsigned integer.", nameof(maxSupply));
        if (ticker is not null && !Bsv20Json.IsTicker(ticker))
            throw new ArgumentException("Ticker must be 4 letters.", nameof(ticker));
        if (mintLimit is not null && !Bsv20Json.IsDigits(mintLimit))
            throw new ArgumentException("Mint limit must be an unsigned integer.", nameof(mintLimit));
        MaxSupply = maxSupply;
        Ticker = ticker;
        MintLimit = mintLimit;
        Decimals = decimals;
    }

    public string? Ticker { get; }

    public string MaxSupply { get; }

    public string? MintLimit { get; }

    public int? Decimals { get; }

    public bool Tickerless => Ticker is null;

    public Inscription ToInscription() => new(ContentType, Encoding.UTF8.GetBytes(ToJson()));

    public string ToJson()
    {
        using var stream = new MemoryStream();
        using (var writer = new Utf8JsonWriter(stream))
        {
            writer.WriteStartObject();
            writer.WriteString("p", Bsv20Json.Protocol);
            writer.WriteString("op", Tickerless ? "deploy+mint" : "deploy");
            if (Tickerless)
                writer.WriteString("amt", MaxSupply);
            else
            {
                writer.WriteString("tick", Ticker);
                writer.WriteString("max", MaxSupply);
                if (MintLimit is not null)
                    writer.WriteString("lim", MintLimit);
            }

            if (Decimals is not null)
                writer.WriteString("dec", Decimals.Value.ToString(CultureInfo.InvariantCulture));
            writer.WriteEndObject();
        }

        return Encoding.UTF8.GetString(stream.ToArray());
    }

    public static bool TryParse(string json, out Bsv20Deploy? deploy)
    {
        deploy = null;
        if (!Bsv20Json.TryOpen(json, out JsonDocument? document))
            return false;
        using (document)
        {
            JsonElement root = document!.RootElement;
            string? op = Bsv20Json.Text(root, "op");
            int? decimals = Bsv20Json.OptionalInt(root, "dec");
            if (decimals is null && root.TryGetProperty("dec", out _))
                return false;
            if (op == "deploy")
            {
                string? tick = Bsv20Json.Text(root, "tick");
                string? max = Bsv20Json.Text(root, "max");
                string? lim = Bsv20Json.Text(root, "lim");
                if (!Bsv20Json.IsTicker(tick) || !Bsv20Json.IsDigits(max) || (lim is not null && !Bsv20Json.IsDigits(lim)))
                    return false;
                deploy = new Bsv20Deploy(max!, tick, lim, decimals);
                return true;
            }

            if (op == "deploy+mint")
            {
                string? amt = Bsv20Json.Text(root, "amt");
                if (!Bsv20Json.IsDigits(amt) || root.TryGetProperty("tick", out _))
                    return false;
                deploy = new Bsv20Deploy(amt!, ticker: null, mintLimit: null, decimals);
                return true;
            }

            return false;
        }
    }
}

internal static class Bsv20Json
{
    public const string Protocol = "bsv-20";

    public const string ContentType = "application/bsv-20";

    public static bool TryOpen(string json, out JsonDocument? document)
    {
        document = null;
        if (string.IsNullOrWhiteSpace(json))
            return false;
        try
        {
            document = JsonDocument.Parse(json);
        }
        catch (JsonException)
        {
            return false;
        }

        if (document.RootElement.ValueKind != JsonValueKind.Object || Text(document.RootElement, "p") != Protocol)
        {
            document.Dispose();
            document = null;
            return false;
        }

        return true;
    }

    public static string? Text(JsonElement root, string name) =>
        root.TryGetProperty(name, out JsonElement value) && value.ValueKind == JsonValueKind.String ? value.GetString() : null;

    public static int? OptionalInt(JsonElement root, string name)
    {
        if (!root.TryGetProperty(name, out JsonElement value))
            return null;
        if (value.ValueKind == JsonValueKind.Number && value.TryGetInt32(out int number) && number >= 0)
            return number;
        if (value.ValueKind == JsonValueKind.String && int.TryParse(value.GetString(), NumberStyles.None, CultureInfo.InvariantCulture, out int parsed) && parsed >= 0)
            return parsed;
        return null;
    }

    public static bool IsTicker(string? text) =>
        text is { Length: 4 } && text.All(char.IsAsciiLetter);

    public static bool IsDigits(string? text) =>
        !string.IsNullOrEmpty(text) && text.All(char.IsAsciiDigit);
}
