using System.Security.Cryptography;

namespace Bsvlib.Crypto;

/// <summary>双重 SHA-256，用于交易号、区块哈希和 Base58Check 校验和。</summary>
public static class Hash256
{
    public const int Size = 32;

    public static byte[] Compute(ReadOnlySpan<byte> data)
    {
        var hash = new byte[Size];
        Write(data, hash);
        return hash;
    }

    public static void Write(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));

        Span<byte> first = stackalloc byte[Size];
        SHA256.HashData(data, first);
        SHA256.HashData(first, destination);
    }
}
