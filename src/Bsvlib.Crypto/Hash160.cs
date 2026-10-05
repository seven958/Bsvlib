using System.Security.Cryptography;

namespace Bsvlib.Crypto;

/// <summary>HASH160 = RIPEMD-160(SHA-256(x))，用于 P2PKH 地址。</summary>
public static class Hash160
{
    public const int Size = Ripemd160.Size;

    public static byte[] Compute(ReadOnlySpan<byte> data)
    {
        var hash = new byte[Size];
        Write(data, hash);
        return hash;
    }

    public static void Write(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        Span<byte> sha = stackalloc byte[32];
        SHA256.HashData(data, sha);
        Ripemd160.Write(sha, destination);
    }
}
