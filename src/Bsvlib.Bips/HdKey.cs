using System.Buffers.Binary;
using System.Security.Cryptography;
using Bsvlib.Core;
using Bsvlib.Crypto;

namespace Bsvlib.Bips;

/// <summary>BIP-32 扩展私钥。主密钥由 HMAC-SHA512("Bitcoin seed", seed) 生成。</summary>
public sealed class HdPrivateKey
{
    private const uint HardenedBit = 0x8000_0000;
    private readonly byte[] _chainCode;

    private HdPrivateKey(Network network, PrivateKey key, byte[] chainCode, byte depth, uint childNumber, uint parentFingerprint)
    {
        Network = network;
        Key = key;
        _chainCode = chainCode;
        Depth = depth;
        ChildNumber = childNumber;
        ParentFingerprint = parentFingerprint;
    }

    public Network Network { get; }

    public PrivateKey Key { get; }

    public byte Depth { get; }

    public uint ChildNumber { get; }

    public uint ParentFingerprint { get; }

    public HdPublicKey PublicKey => new(Network, Key.GetPublicKey(), _chainCode, Depth, ChildNumber, ParentFingerprint);

    public static HdPrivateKey FromSeed(ReadOnlySpan<byte> seed, Network network)
    {
        if (!TryFromSeed(seed, network, out HdPrivateKey? key))
            throw new ArgumentException("Seed must be 16 to 64 bytes and produce a valid master key.", nameof(seed));
        return key!;
    }

    public static bool TryFromSeed(ReadOnlySpan<byte> seed, Network network, out HdPrivateKey? key)
    {
        key = null;
        ArgumentNullException.ThrowIfNull(network);
        if (seed.Length is < 16 or > 64)
            return false;

        byte[] hash = HMACSHA512.HashData("Bitcoin seed"u8, seed);
        if (!PrivateKey.TryCreate(hash.AsSpan(0, 32), out PrivateKey? master))
            return false;

        key = new HdPrivateKey(network, master!, hash[32..], depth: 0, childNumber: 0, parentFingerprint: 0);
        return true;
    }

    public HdPrivateKey Derive(uint index)
    {
        if (!TryDerive(index, out HdPrivateKey? child))
            throw new InvalidOperationException($"Derivation index {index} is not usable.");
        return child!;
    }

    public bool TryDerive(uint index, out HdPrivateKey? child)
    {
        child = null;
        if (Depth == byte.MaxValue)
            return false;

        Span<byte> data = stackalloc byte[37];
        if (index >= HardenedBit)
        {
            data[0] = 0;
            Key.WriteTo(data[1..]);
        }
        else
        {
            Key.GetPublicKey().WriteTo(data);
        }

        BinaryPrimitives.WriteUInt32BigEndian(data[^4..], index);
        byte[] hash = HMACSHA512.HashData(_chainCode, data);
        if (!Key.TryAddTweak(hash.AsSpan(0, 32), out PrivateKey? derived))
            return false;

        child = new HdPrivateKey(Network, derived!, hash[32..], (byte)(Depth + 1), index, Fingerprint(Key));
        return true;
    }

    public HdPrivateKey DerivePath(string path)
    {
        if (!TryDerivePath(path, out HdPrivateKey? key))
            throw new FormatException($"Cannot derive path '{path}'.");
        return key!;
    }

    public bool TryDerivePath(string path, out HdPrivateKey? key)
    {
        key = this;
        if (!TryParsePath(path, out uint[]? indexes))
        {
            key = null;
            return false;
        }

        foreach (uint index in indexes!)
        {
            if (!key!.TryDerive(index, out key))
                return false;
        }

        return true;
    }

    public string ToExtendedKey() => Encode(Network.ExtendedPrivateKeyVersion.Span, Depth, ParentFingerprint, ChildNumber, _chainCode, PrivatePayload());

    public static bool TryParse(string text, Network network, out HdPrivateKey? key)
    {
        key = null;
        ArgumentNullException.ThrowIfNull(network);
        if (!TryDecode(text, network.ExtendedPrivateKeyVersion.Span, out byte depth, out uint fingerprint, out uint childNumber, out byte[]? chainCode, out byte[]? payload))
            return false;
        if (payload![0] != 0 || !PrivateKey.TryCreate(payload.AsSpan(1), out PrivateKey? privateKey))
            return false;

        key = new HdPrivateKey(network, privateKey!, chainCode!, depth, childNumber, fingerprint);
        return true;
    }

    internal static bool TryParsePath(string path, out uint[]? indexes)
    {
        indexes = null;
        if (string.IsNullOrWhiteSpace(path))
            return false;

        string[] parts = path.Split('/', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0 || (parts[0] != "m" && parts[0] != "M"))
            return false;

        var result = new uint[parts.Length - 1];
        for (int i = 1; i < parts.Length; i++)
        {
            string part = parts[i];
            bool hardened = part.EndsWith('\'') || part.EndsWith('h') || part.EndsWith('H');
            if (hardened)
                part = part[..^1];
            if (!uint.TryParse(part, System.Globalization.NumberStyles.None, System.Globalization.CultureInfo.InvariantCulture, out uint index))
                return false;
            if (hardened)
            {
                if (index >= HardenedBit)
                    return false;
                index += HardenedBit;
            }
            else if (index >= HardenedBit)
            {
                return false;
            }

            result[i - 1] = index;
        }

        indexes = result;
        return true;
    }

    internal static string Encode(ReadOnlySpan<byte> version, byte depth, uint parentFingerprint, uint childNumber, ReadOnlySpan<byte> chainCode, ReadOnlySpan<byte> keyPayload)
    {
        var data = new byte[78];
        version.CopyTo(data);
        data[4] = depth;
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(5), parentFingerprint);
        BinaryPrimitives.WriteUInt32BigEndian(data.AsSpan(9), childNumber);
        chainCode.CopyTo(data.AsSpan(13));
        keyPayload.CopyTo(data.AsSpan(45));
        return Base58Check.Encode(data);
    }

    internal static bool TryDecode(string text, ReadOnlySpan<byte> version, out byte depth, out uint parentFingerprint, out uint childNumber, out byte[]? chainCode, out byte[]? keyPayload)
    {
        depth = 0;
        parentFingerprint = 0;
        childNumber = 0;
        chainCode = null;
        keyPayload = null;
        if (text is null || !Base58Check.TryDecode(text, out byte[] raw) || raw.Length != 78)
            return false;
        if (!raw.AsSpan(0, 4).SequenceEqual(version))
            return false;

        depth = raw[4];
        parentFingerprint = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(5));
        childNumber = BinaryPrimitives.ReadUInt32BigEndian(raw.AsSpan(9));
        if (depth == 0 && (parentFingerprint != 0 || childNumber != 0))
            return false;

        chainCode = raw[13..45];
        keyPayload = raw[45..78];
        return true;
    }

    private byte[] PrivatePayload()
    {
        var payload = new byte[33];
        Key.WriteTo(payload.AsSpan(1));
        return payload;
    }

    private static uint Fingerprint(PrivateKey key)
    {
        Span<byte> hash = stackalloc byte[20];
        Hash160.Write(key.GetPublicKey().ToBytes(), hash);
        return BinaryPrimitives.ReadUInt32BigEndian(hash);
    }
}

/// <summary>BIP-32 扩展公钥。只能派生子索引，不能派生硬化索引。</summary>
public sealed class HdPublicKey
{
    private const uint HardenedBit = 0x8000_0000;
    private readonly byte[] _chainCode;

    internal HdPublicKey(Network network, PublicKey key, byte[] chainCode, byte depth, uint childNumber, uint parentFingerprint)
    {
        Network = network;
        Key = key;
        _chainCode = (byte[])chainCode.Clone();
        Depth = depth;
        ChildNumber = childNumber;
        ParentFingerprint = parentFingerprint;
    }

    public Network Network { get; }

    public PublicKey Key { get; }

    public byte Depth { get; }

    public uint ChildNumber { get; }

    public uint ParentFingerprint { get; }

    public HdPublicKey Derive(uint index)
    {
        if (!TryDerive(index, out HdPublicKey? child))
            throw new InvalidOperationException($"Public derivation cannot use index {index}.");
        return child!;
    }

    public bool TryDerive(uint index, out HdPublicKey? child)
    {
        child = null;
        if (index >= HardenedBit || Depth == byte.MaxValue)
            return false;

        Span<byte> data = stackalloc byte[37];
        Key.WriteTo(data);
        BinaryPrimitives.WriteUInt32BigEndian(data[^4..], index);
        byte[] hash = HMACSHA512.HashData(_chainCode, data);
        if (!Key.TryAddTweak(hash.AsSpan(0, 32), out PublicKey? derived))
            return false;

        Span<byte> parentHash = stackalloc byte[20];
        Hash160.Write(Key.ToBytes(), parentHash);
        uint fingerprint = BinaryPrimitives.ReadUInt32BigEndian(parentHash);
        child = new HdPublicKey(Network, derived!, hash[32..], (byte)(Depth + 1), index, fingerprint);
        return true;
    }

    public string ToExtendedKey()
    {
        var payload = new byte[33];
        Key.WriteTo(payload);
        return HdPrivateKey.Encode(Network.ExtendedPublicKeyVersion.Span, Depth, ParentFingerprint, ChildNumber, _chainCode, payload);
    }

    public static bool TryParse(string text, Network network, out HdPublicKey? key)
    {
        key = null;
        ArgumentNullException.ThrowIfNull(network);
        if (!HdPrivateKey.TryDecode(text, network.ExtendedPublicKeyVersion.Span, out byte depth, out uint fingerprint, out uint childNumber, out byte[]? chainCode, out byte[]? payload))
            return false;
        if (!PublicKey.TryCreate(payload, out PublicKey? publicKey) || !publicKey!.Compressed)
            return false;

        key = new HdPublicKey(network, publicKey, chainCode!, depth, childNumber, fingerprint);
        return true;
    }
}
