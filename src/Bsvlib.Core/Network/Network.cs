using Bsvlib.Crypto;

namespace Bsvlib.Core;

/// <summary>BSV 网络参数，取值与 bitcoin-sv 的 chainparams 一致。</summary>
public sealed class Network
{
    private Network(
        string name,
        byte[] magic,
        byte publicKeyVersion,
        byte scriptVersion,
        byte privateKeyVersion,
        byte[] extendedPublicVersion,
        byte[] extendedPrivateVersion,
        int defaultPort)
    {
        Name = name;
        Magic = magic;
        PublicKeyAddressVersion = publicKeyVersion;
        ScriptAddressVersion = scriptVersion;
        PrivateKeyVersion = privateKeyVersion;
        ExtendedPublicKeyVersion = extendedPublicVersion;
        ExtendedPrivateKeyVersion = extendedPrivateVersion;
        DefaultPort = defaultPort;
    }

    public static Network Mainnet { get; } = new(
        "mainnet", [0xE3, 0xE1, 0xF3, 0xE8], 0x00, 0x05, 0x80, [0x04, 0x88, 0xB2, 0x1E], [0x04, 0x88, 0xAD, 0xE4], 8333);

    public static Network Testnet { get; } = new(
        "testnet", [0xF4, 0xE5, 0xF3, 0xF4], 0x6F, 0xC4, 0xEF, [0x04, 0x35, 0x87, 0xCF], [0x04, 0x35, 0x83, 0x94], 18333);

    public static Network ScalingTestnet { get; } = new(
        "stn", [0xFB, 0xCE, 0xC4, 0xF9], 0x6F, 0xC4, 0xEF, [0x04, 0x35, 0x87, 0xCF], [0x04, 0x35, 0x83, 0x94], 9333);

    public static Network Regtest { get; } = new(
        "regtest", [0xDA, 0xB5, 0xBF, 0xFA], 0x6F, 0xC4, 0xEF, [0x04, 0x35, 0x87, 0xCF], [0x04, 0x35, 0x83, 0x94], 18444);

    public string Name { get; }

    public ReadOnlyMemory<byte> Magic { get; }

    public byte PublicKeyAddressVersion { get; }

    public byte ScriptAddressVersion { get; }

    public byte PrivateKeyVersion { get; }

    public ReadOnlyMemory<byte> ExtendedPublicKeyVersion { get; }

    public ReadOnlyMemory<byte> ExtendedPrivateKeyVersion { get; }

    public int DefaultPort { get; }
}

public enum AddressKind
{
    P2pkh,
    P2sh,
}

public sealed class Address
{
    private readonly byte[] _hash;

    private Address(Network network, AddressKind kind, byte[] hash, Script lockingScript)
    {
        Network = network;
        Kind = kind;
        _hash = hash;
        LockingScript = lockingScript;
    }

    public Network Network { get; }

    public AddressKind Kind { get; }

    public ReadOnlyMemory<byte> Hash => _hash;

    public Script LockingScript { get; }

    public static Address P2pkh(ReadOnlySpan<byte> hash160, Network network)
    {
        ArgumentNullException.ThrowIfNull(network);
        if (hash160.Length != 20)
            throw new ArgumentException("Hash must be 20 bytes.", nameof(hash160));
        var hash = hash160.ToArray();
        return new Address(network, AddressKind.P2pkh, hash, Script.P2pkhLock(hash));
    }

    public static Address P2sh(ReadOnlySpan<byte> hash160, Network network)
    {
        ArgumentNullException.ThrowIfNull(network);
        if (hash160.Length != 20)
            throw new ArgumentException("Hash must be 20 bytes.", nameof(hash160));
        var hash = hash160.ToArray();
        return new Address(network, AddressKind.P2sh, hash, Script.P2shLock(hash));
    }

    public static Address FromPublicKey(PublicKey key, Network network)
    {
        ArgumentNullException.ThrowIfNull(key);
        Span<byte> hash = stackalloc byte[20];
        Hash160.Write(key.ToBytes(), hash);
        return P2pkh(hash, network);
    }

    public static bool TryParse(string text, Network network, out Address? address)
    {
        address = null;
        ArgumentNullException.ThrowIfNull(network);
        if (text is null || !Base58Check.TryDecode(text, out byte[] payload) || payload.Length != 21)
            return false;

        AddressKind kind;
        if (payload[0] == network.PublicKeyAddressVersion)
            kind = AddressKind.P2pkh;
        else if (payload[0] == network.ScriptAddressVersion)
            kind = AddressKind.P2sh;
        else
            return false;

        address = kind == AddressKind.P2pkh
            ? P2pkh(payload.AsSpan(1), network)
            : P2sh(payload.AsSpan(1), network);
        return true;
    }

    public override string ToString()
    {
        var payload = new byte[21];
        payload[0] = Kind == AddressKind.P2pkh ? Network.PublicKeyAddressVersion : Network.ScriptAddressVersion;
        _hash.CopyTo(payload, 1);
        return Base58Check.Encode(payload);
    }
}

public static class Wif
{
    public static string Encode(PrivateKey key, Network network, bool compressed = true)
    {
        ArgumentNullException.ThrowIfNull(key);
        ArgumentNullException.ThrowIfNull(network);
        var payload = new byte[compressed ? 34 : 33];
        payload[0] = network.PrivateKeyVersion;
        key.WriteTo(payload.AsSpan(1));
        if (compressed)
            payload[33] = 0x01;
        return Base58Check.Encode(payload);
    }

    public static bool TryDecode(string text, Network network, out PrivateKey? key, out bool compressed)
    {
        key = null;
        compressed = false;
        ArgumentNullException.ThrowIfNull(network);
        if (text is null || !Base58Check.TryDecode(text, out byte[] payload))
            return false;
        if (payload.Length == 34)
        {
            if (payload[33] != 0x01)
                return false;
            compressed = true;
        }
        else if (payload.Length != 33)
        {
            return false;
        }

        if (payload[0] != network.PrivateKeyVersion)
            return false;
        return PrivateKey.TryCreate(payload.AsSpan(1, 32), out key);
    }
}
