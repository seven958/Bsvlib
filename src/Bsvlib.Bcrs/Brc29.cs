using Bsvlib.Core;
using Bsvlib.Crypto;

namespace Bsvlib.Bcrs;

/// <summary>BRC-29。用 BRC-42 为收款方派生一把 P2PKH 密钥。</summary>
public static class Brc29
{
    public const int SecurityLevel = 2;

    public const string ProtocolName = "3241645161d8";

    public static string KeyId(string derivationPrefix, string derivationSuffix) =>
        derivationPrefix + " " + derivationSuffix;

    public static string InvoiceNumber(string derivationPrefix, string derivationSuffix) =>
        KeyDerivation.InvoiceNumber(SecurityLevel, ProtocolName, KeyId(derivationPrefix, derivationSuffix));

    public static PublicKey DerivePublicKey(PrivateKey sender, PublicKey recipient, string derivationPrefix, string derivationSuffix)
    {
        if (!KeyDerivation.TryDerivePublic(sender, recipient, InvoiceNumber(derivationPrefix, derivationSuffix), out PublicKey? key))
            throw new InvalidOperationException("BRC-29 public derivation produced an unusable scalar.");
        return key!;
    }

    public static PrivateKey DerivePrivateKey(PrivateKey recipient, PublicKey sender, string derivationPrefix, string derivationSuffix)
    {
        if (!KeyDerivation.TryDerivePrivate(recipient, sender, InvoiceNumber(derivationPrefix, derivationSuffix), out PrivateKey? key))
            throw new InvalidOperationException("BRC-29 private derivation produced an unusable scalar.");
        return key!;
    }

    public static Script LockingScript(PrivateKey sender, PublicKey recipient, string derivationPrefix, string derivationSuffix)
    {
        Span<byte> hash = stackalloc byte[20];
        Hash160.Write(DerivePublicKey(sender, recipient, derivationPrefix, derivationSuffix).ToBytes(), hash);
        return Script.P2pkhLock(hash);
    }
}
