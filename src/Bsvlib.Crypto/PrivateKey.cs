using NBitcoin.Secp256k1;

namespace Bsvlib.Crypto;

/// <summary>
/// secp256k1 私钥。标量必须落在 [1, n-1]，越界直接拒绝。
/// 签名使用 RFC 6979，输出 low-S。
/// </summary>
public sealed class PrivateKey
{
    public const int Size = 32;

    private readonly byte[] _scalar;

    private PrivateKey(byte[] scalar) => _scalar = scalar;

    public static bool TryCreate(ReadOnlySpan<byte> scalar, out PrivateKey? key)
    {
        key = null;
        if (scalar.Length != Size || !ECPrivKey.TryCreate(scalar, out ECPrivKey? parsed) || parsed is null)
            return false;

        parsed.Dispose();
        var copy = new byte[Size];
        scalar.CopyTo(copy);
        key = new PrivateKey(copy);
        return true;
    }

    public void WriteTo(Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));
        _scalar.CopyTo(destination);
    }

    public byte[] ToBytes()
    {
        var copy = new byte[Size];
        _scalar.CopyTo(copy);
        return copy;
    }

    public PublicKey GetPublicKey(bool compressed = true)
    {
        using ECPrivKey secret = Open();
        return PublicKey.FromPoint(secret.CreatePubKey(), compressed);
    }

    /// <summary>把本私钥乘到对方公钥上，写出 33 字节压缩点。BRC-42 用它做共享秘密。</summary>
    public void WriteSharedPoint(PublicKey point, Span<byte> compressed)
    {
        ArgumentNullException.ThrowIfNull(point);
        if (compressed.Length < 33)
            throw new ArgumentException("Destination must be at least 33 bytes.", nameof(compressed));
        using ECPrivKey secret = Open();
        point.Multiply(secret).WriteToSpan(true, compressed, out _);
    }

    /// <summary>对 32 字节摘要签名，写入 64 字节紧凑形式 r‖s。</summary>
    public void SignDigest(ReadOnlySpan<byte> digest, Span<byte> compactSignature)
    {
        if (digest.Length != 32)
            throw new ArgumentException("Digest must be 32 bytes.", nameof(digest));
        if (compactSignature.Length < 64)
            throw new ArgumentException("Destination must be at least 64 bytes.", nameof(compactSignature));

        using ECPrivKey secret = Open();
        secret.SignECDSARFC6979(digest).WriteCompactToSpan(compactSignature[..64]);
    }

    public byte[] SignDigest(ReadOnlySpan<byte> digest)
    {
        var signature = new byte[64];
        SignDigest(digest, signature);
        return signature;
    }

    /// <summary>child = (key + tweak) mod n。tweak 越界或结果为 0 时返回 false。</summary>
    public bool TryAddTweak(ReadOnlySpan<byte> tweak, out PrivateKey? child)
    {
        child = null;
        if (tweak.Length != Size)
            return false;

        using ECPrivKey secret = Open();
        if (!secret.TryTweakAdd(tweak, out ECPrivKey? tweaked) || tweaked is null)
            return false;

        using (tweaked)
        {
            var scalar = new byte[Size];
            tweaked.WriteToSpan(scalar);
            child = new PrivateKey(scalar);
            return true;
        }
    }

    /// <summary>对 32 字节摘要签名，返回 DER。脚本层再在后面附加 Sighash 类型字节。</summary>
    public byte[] SignDigestDer(ReadOnlySpan<byte> digest)
    {
        if (digest.Length != 32)
            throw new ArgumentException("Digest must be 32 bytes.", nameof(digest));

        using ECPrivKey secret = Open();
        return secret.SignECDSARFC6979(digest).ToDER();
    }

    private ECPrivKey Open()
    {
        if (!ECPrivKey.TryCreate(_scalar, out ECPrivKey? secret) || secret is null)
            throw new InvalidOperationException("Stored scalar is no longer a valid private key.");
        return secret;
    }
}
