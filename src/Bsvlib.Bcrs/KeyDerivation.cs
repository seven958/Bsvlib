using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Bsvlib.Crypto;

namespace Bsvlib.Bcrs;

/// <summary>
/// BRC-42。共享秘密是私钥乘对方公钥后的压缩点，HMAC-SHA256 的消息是 UTF-8 发票号。
/// </summary>
public static class KeyDerivation
{
    private static readonly BigInteger Order = BigInteger.Parse(
        "00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
        NumberStyles.HexNumber);

    public static bool TryDerivePrivate(PrivateKey self, PublicKey counterparty, string invoiceNumber, out PrivateKey? derived)
    {
        derived = null;
        if (!TryTweak(self, counterparty, invoiceNumber, out byte[]? tweak))
            return false;
        return self.TryAddTweak(tweak, out derived);
    }

    public static bool TryDerivePublic(PrivateKey self, PublicKey counterparty, string invoiceNumber, out PublicKey? derived)
    {
        derived = null;
        if (!TryTweak(self, counterparty, invoiceNumber, out byte[]? tweak))
            return false;
        return counterparty.TryAddTweak(tweak, out derived);
    }

    public static string InvoiceNumber(int securityLevel, string protocolName, string keyId)
    {
        if (securityLevel is < 0 or > 2)
            throw new ArgumentOutOfRangeException(nameof(securityLevel));
        ArgumentException.ThrowIfNullOrEmpty(protocolName);
        ArgumentException.ThrowIfNullOrEmpty(keyId);
        return string.Create(CultureInfo.InvariantCulture, $"{securityLevel}-{protocolName.ToLowerInvariant().Trim()}-{keyId}");
    }

    private static bool TryTweak(PrivateKey self, PublicKey counterparty, string invoiceNumber, out byte[]? tweak)
    {
        tweak = null;
        ArgumentNullException.ThrowIfNull(self);
        ArgumentNullException.ThrowIfNull(counterparty);
        if (invoiceNumber is null)
            return false;

        Span<byte> shared = stackalloc byte[33];
        self.WriteSharedPoint(counterparty, shared);
        byte[] hmac = HMACSHA256.HashData(shared, Encoding.UTF8.GetBytes(invoiceNumber));
        var scalar = new BigInteger(hmac, isUnsigned: true, isBigEndian: true) % Order;
        if (scalar.IsZero)
            return false;

        byte[] raw = scalar.ToByteArray(isUnsigned: true, isBigEndian: true);
        tweak = new byte[32];
        raw.CopyTo(tweak, 32 - raw.Length);
        return true;
    }
}
