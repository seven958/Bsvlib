using System.Text;

namespace Bsvlib.Protocols;

/// <summary>一笔铭文。字段沿用 ord 的标签：1 是内容类型，3 是父铭文，5 是元数据。</summary>
public sealed class Inscription
{
    public const int ContentTypeTag = 1;

    public const int ParentTag = 3;

    public const int MetadataTag = 5;

    public Inscription(string? contentType, ReadOnlySpan<byte> body, ReadOnlySpan<byte> metadata = default, ReadOnlySpan<byte> parent = default)
    {
        ContentType = contentType;
        Body = body.ToArray();
        Metadata = metadata.IsEmpty ? null : metadata.ToArray();
        Parent = parent.IsEmpty ? null : parent.ToArray();
    }

    public string? ContentType { get; }

    public byte[] Body { get; }

    public byte[]? Metadata { get; }

    public byte[]? Parent { get; }

    public string FormatId(Bsvlib.Core.TxId transaction, int output) =>
        string.Create(System.Globalization.CultureInfo.InvariantCulture, $"{transaction}_{output}");

    public string BodyText => Encoding.UTF8.GetString(Body);
}
