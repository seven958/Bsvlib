using NBitcoin.Secp256k1;

namespace Bsvlib.Crypto;

/// <summary>SEC 1 公钥，接受 33 字节压缩形式和 65 字节未压缩形式。验签拒绝 high-S。</summary>
public sealed class PublicKey : IEquatable<PublicKey>
{
    private readonly ECPubKey _point;
    private readonly bool _compressed;

    private PublicKey(ECPubKey point, bool compressed)
    {
        _point = point;
        _compressed = compressed;
    }

    public bool Compressed => _compressed;

    public int Size => _compressed ? 33 : 65;

    public static bool TryCreate(ReadOnlySpan<byte> encoded, out PublicKey? key)
    {
        key = null;
        if (!ECPubKey.TryCreate(encoded, null, out bool compressed, out ECPubKey? point) || point is null)
            return false;

        key = new PublicKey(point, compressed);
        return true;
    }

    internal static PublicKey FromPoint(ECPubKey point, bool compressed) => new(point, compressed);

    internal ECPubKey Multiply(ECPrivKey scalar) => _point.GetSharedPubkey(scalar);

    public void WriteTo(Span<byte> destination) => WriteTo(destination, _compressed);

    public void WriteTo(Span<byte> destination, bool compressed)
    {
        int size = compressed ? 33 : 65;
        if (destination.Length < size)
            throw new ArgumentException($"Destination must be at least {size} bytes.", nameof(destination));
        _point.WriteToSpan(compressed, destination, out _);
    }

    public byte[] ToBytes() => ToBytes(_compressed);

    public byte[] ToBytes(bool compressed)
    {
        var encoded = new byte[compressed ? 33 : 65];
        WriteTo(encoded, compressed);
        return encoded;
    }

    /// <summary>child = point + tweak·G。tweak 越界或结果为无穷远点时返回 false。</summary>
    public bool TryAddTweak(ReadOnlySpan<byte> tweak, out PublicKey? child)
    {
        child = null;
        if (tweak.Length != 32 || !_point.TryAddTweak(tweak, out ECPubKey? tweaked) || tweaked is null)
            return false;

        child = new PublicKey(tweaked, compressed: true);
        return true;
    }

    /// <summary>验证 64 字节紧凑签名或 DER 签名。摘要必须是 32 字节。</summary>
    public bool VerifyDigest(ReadOnlySpan<byte> digest, ReadOnlySpan<byte> signature)
    {
        if (digest.Length != 32)
            return false;

        if (!TryReadSignature(signature, out SecpECDSASignature? parsed) || parsed is null)
            return false;

        return _point.SigVerify(parsed, digest);
    }

    public bool Equals(PublicKey? other) => other is not null && _point == other._point;

    public override bool Equals(object? obj) => obj is PublicKey other && Equals(other);

    public override int GetHashCode() => _point.GetHashCode();

    private static bool TryReadSignature(ReadOnlySpan<byte> signature, out SecpECDSASignature? parsed)
    {
        if (signature.Length == 64)
            return SecpECDSASignature.TryCreateFromCompact(signature, out parsed);

        return SecpECDSASignature.TryCreateFromDer(signature, out parsed);
    }
}
