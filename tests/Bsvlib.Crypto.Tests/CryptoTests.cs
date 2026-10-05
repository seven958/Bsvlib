using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Bsvlib.Crypto;
using Xunit;

namespace Bsvlib.Crypto.Tests;

file static class HexCodec
{
    public static string Format(ReadOnlySpan<byte> data) => Convert.ToHexString(data).ToLowerInvariant();

    public static byte[] Parse(string hex)
    {
        var bytes = new byte[hex.Length / 2];
        for (int i = 0; i < bytes.Length; i++)
            bytes[i] = byte.Parse(hex.AsSpan(i * 2, 2), NumberStyles.HexNumber);
        return bytes;
    }
}

public class HashTests
{
    [Fact]
    public void Sha256d_of_empty_matches_the_published_digest()
    {
        Assert.Equal(
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
            HexCodec.Format(Hash256.Compute([])));
    }

    [Theory]
    [InlineData("", "9c1185a5c5e9fc54612808977ee8f548b2258d31")]
    [InlineData("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc")]
    [InlineData("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36")]
    [InlineData("abcdefghijklmnopqrstuvwxyz", "f71c27109c692c1b56bbdceb5b9d2865b3708dbc")]
    [InlineData("The quick brown fox jumps over the lazy dog", "37f332f68db77bd9d7edd4969571ad671cf9dd3b")]
    [InlineData("12345678901234567890123456789012345678901234567890123456789012345678901234567890", "9b752e45573d4b39f4dbd3323cab82bf63326bfb")]
    public void Ripemd160_matches_standard_vectors(string text, string expected)
    {
        Assert.Equal(expected, HexCodec.Format(Ripemd160.Compute(Encoding.ASCII.GetBytes(text))));
    }

    [Fact]
    public void Hash160_of_the_canonical_pubkey_is_the_published_address()
    {
        byte[] pub = HexCodec.Parse("0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352");
        Assert.Equal("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31", HexCodec.Format(Hash160.Compute(pub)));

        byte[] payload = new byte[21];
        payload[0] = 0x00;
        Hash160.Write(pub, payload.AsSpan(1));
        Assert.Equal("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", Base58Check.Encode(payload));
    }
}

public class Base58CheckTests
{
    [Fact]
    public void Round_trip_preserves_the_payload_and_rejects_a_bad_checksum()
    {
        byte[] payload = HexCodec.Parse("00f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");
        string encoded = Base58Check.Encode(payload);
        Assert.True(Base58Check.TryDecode(encoded, out byte[] decoded));
        Assert.Equal(payload, decoded);

        string corrupt = encoded[..^1] + (encoded[^1] == 's' ? "t" : "s");
        Assert.False(Base58Check.TryDecode(corrupt, out _));
        Assert.False(Base58Check.TryDecode("0OIl", out _));
        Assert.False(Base58Check.TryDecode("", out _));
    }
}

public class KeyTests
{
    private static readonly BigInteger Order = BigInteger.Parse(
        "00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        NumberStyles.HexNumber);

    [Theory]
    [InlineData(1, "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798")]
    [InlineData(2, "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5")]
    public void Compressed_public_key_matches_the_generator_multiples(int scalar, string expected)
    {
        Assert.True(PrivateKey.TryCreate(Scalar(scalar), out PrivateKey? key));
        Assert.Equal(expected, HexCodec.Format(key!.GetPublicKey().ToBytes()));
    }

    [Fact]
    public void Uncompressed_generator_uses_the_04_prefix()
    {
        Assert.True(PrivateKey.TryCreate(Scalar(1), out PrivateKey? key));
        Assert.Equal(
            "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8",
            HexCodec.Format(key!.GetPublicKey(compressed: false).ToBytes()));
    }

    [Fact]
    public void Out_of_range_scalars_are_rejected()
    {
        Assert.False(PrivateKey.TryCreate(new byte[32], out _));
        Assert.False(PrivateKey.TryCreate(To32(Order), out _));
        Assert.False(PrivateKey.TryCreate(To32(Order + 1), out _));
        Assert.False(PrivateKey.TryCreate(new byte[31], out _));
        Assert.False(PrivateKey.TryCreate(Enumerable.Repeat((byte)0xff, 32).ToArray(), out _));
    }

    [Fact]
    public void Parsed_public_key_round_trips_both_encodings()
    {
        Assert.True(PrivateKey.TryCreate(Scalar(1), out PrivateKey? key));
        byte[] compressed = key!.GetPublicKey().ToBytes();
        byte[] uncompressed = key.GetPublicKey(compressed: false).ToBytes();

        Assert.True(PublicKey.TryCreate(compressed, out PublicKey? fromCompressed));
        Assert.True(PublicKey.TryCreate(uncompressed, out PublicKey? fromUncompressed));
        Assert.True(fromCompressed!.Compressed);
        Assert.False(fromUncompressed!.Compressed);
        Assert.Equal(fromCompressed, fromUncompressed);
        Assert.Equal(compressed, fromUncompressed.ToBytes(compressed: true));
        Assert.False(PublicKey.TryCreate(new byte[33], out _));
        Assert.False(PublicKey.TryCreate(new byte[65], out _));
    }

    [Fact]
    public void Adding_tweak_one_to_the_generator_key_yields_two_g()
    {
        Assert.True(PrivateKey.TryCreate(Scalar(1), out PrivateKey? key));
        Assert.True(key!.TryAddTweak(Scalar(1), out PrivateKey? child));
        Assert.Equal(
            "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5",
            HexCodec.Format(child!.GetPublicKey().ToBytes()));
        Assert.True(key.GetPublicKey().TryAddTweak(Scalar(1), out PublicKey? point));
        Assert.Equal(child.GetPublicKey(), point);
    }

    [Fact]
    public void Rfc6979_signatures_are_deterministic_low_s_and_reject_the_high_s_sibling()
    {
        Assert.True(PrivateKey.TryCreate(Scalar(1), out PrivateKey? key));
        byte[] digest = SHA256.HashData("bsvlib"u8.ToArray());
        byte[] first = key!.SignDigest(digest);
        byte[] second = key.SignDigest(digest);
        Assert.Equal(first, second);
        Assert.Equal(
            "46263036c715eaf03b27baf43dc6f9f07216b4cbc058ee94b710f2a4beed89e652a0b260bca41173e2e1ccf70c64db9b9319ef70965346fdc6418545709b29e5",
            HexCodec.Format(first));

        PublicKey pub = key.GetPublicKey();
        Assert.True(pub.VerifyDigest(digest, first));
        Assert.True(pub.VerifyDigest(digest, key.SignDigestDer(digest)));
        Assert.False(pub.VerifyDigest(digest, HighS(first)));
        Assert.False(pub.VerifyDigest(new byte[31], first));
        Assert.False(pub.VerifyDigest(digest, new byte[64]));
    }

    private static byte[] Scalar(int value)
    {
        var scalar = new byte[32];
        scalar[^1] = (byte)value;
        return scalar;
    }

    private static byte[] To32(BigInteger value)
    {
        byte[] raw = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == 33 && raw[0] == 0)
            raw = raw[1..];
        var scalar = new byte[32];
        raw.CopyTo(scalar, 32 - raw.Length);
        return scalar;
    }

    private static byte[] HighS(byte[] compact)
    {
        var high = (byte[])compact.Clone();
        var s = new BigInteger(compact.AsSpan(32), isUnsigned: true, isBigEndian: true);
        To32(Order - s).CopyTo(high, 32);
        return high;
    }
}
