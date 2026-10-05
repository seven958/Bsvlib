using Bsvlib.Bcrs;
using Bsvlib.Core;
using Bsvlib.Crypto;
using Xunit;

namespace Bsvlib.Bcrs.Tests;

public class BrcTests
{
    [Theory]
    [InlineData("033f9160df035156f1c48e75eae99914fa1a1546bec19781e8eddb900200bff9d1", "6a1751169c111b4667a6539ee1be6b7cd9f6e9c8fe011a5f2fe31e03a15e0ede", "f3WCaUmnN9U=", "761656715bbfa172f8f9f58f5af95d9d0dfd69014cfdcacc9a245a10ff8893ef")]
    [InlineData("027775fa43959548497eb510541ac34b01d5ee9ea768de74244a4a25f7b60fae8d", "cab2500e206f31bc18a8af9d6f44f0b9a208c32d5cca2b22acfe9d1a213b2f36", "2Ska++APzEc=", "09f2b48bd75f4da6429ac70b5dce863d5ed2b350b6f2119af5626914bdb7c276")]
    public void Brc42_private_derivation_matches_the_published_vectors(string senderPub, string recipient, string invoice, string expected)
    {
        Assert.True(PublicKey.TryCreate(Convert.FromHexString(senderPub), out PublicKey? sender));
        Assert.True(PrivateKey.TryCreate(Convert.FromHexString(recipient), out PrivateKey? key));
        Assert.True(KeyDerivation.TryDerivePrivate(key!, sender!, invoice, out PrivateKey? derived));
        Assert.Equal(expected, Convert.ToHexString(derived!.ToBytes()).ToLowerInvariant());
    }

    [Theory]
    [InlineData("583755110a8c059de5cd81b8a04e1be884c46083ade3f779c1e022f6f89da94c", "02c0c1e1a1f7d247827d1bcf399f0ef2deef7695c322fd91a01a91378f101b6ffc", "IBioA4D/OaE=", "03c1bf5baadee39721ae8c9882b3cf324f0bf3b9eb3fc1b8af8089ca7a7c2e669f")]
    [InlineData("2c378b43d887d72200639890c11d79e8f22728d032a5733ba3d7be623d1bb118", "039a9da906ecb8ced5c87971e9c2e7c921e66ad450fd4fc0a7d569fdb5bede8e0f", "PWYuo9PDKvI=", "0398cdf4b56a3b2e106224ff3be5253afd5b72de735d647831be51c713c9077848")]
    public void Brc42_public_derivation_matches_the_published_vectors(string sender, string recipientPub, string invoice, string expected)
    {
        Assert.True(PrivateKey.TryCreate(Convert.FromHexString(sender), out PrivateKey? key));
        Assert.True(PublicKey.TryCreate(Convert.FromHexString(recipientPub), out PublicKey? recipient));
        Assert.True(KeyDerivation.TryDerivePublic(key!, recipient!, invoice, out PublicKey? derived));
        Assert.Equal(expected, Convert.ToHexString(derived!.ToBytes()).ToLowerInvariant());
    }

    [Fact]
    public void Brc29_recipient_can_spend_the_key_the_sender_derived()
    {
        Assert.True(PrivateKey.TryCreate(Scalar(1), out PrivateKey? senderKey));
        Assert.True(PrivateKey.TryCreate(Scalar(2), out PrivateKey? recipientKey));
        PrivateKey sender = senderKey!;
        PrivateKey recipient = recipientKey!;
        PublicKey recipientPub = recipient.GetPublicKey();
        PublicKey derivedPub = Brc29.DerivePublicKey(sender, recipientPub, "invoice", "output-0");
        PrivateKey derivedPriv = Brc29.DerivePrivateKey(recipient, sender.GetPublicKey(), "invoice", "output-0");
        Assert.Equal(derivedPub, derivedPriv.GetPublicKey());

        Script locking = Brc29.LockingScript(sender, recipientPub, "invoice", "output-0");
        var builder = new TransactionBuilder()
            .AddInput(new OutPoint(TxId.Parse(new string('1', 64)), 0), new Satoshis(5_000), locking)
            .AddOutput(new Satoshis(4_000), Script.P2pkhLock(new byte[20]));
        builder.SignP2pkh(0, derivedPriv);
        Transaction tx = builder.Build();
        Assert.True(ScriptInterpreter.Verify(tx.Inputs[0].UnlockingScript, locking, new TransactionSignatureChecker(tx, 0, new Satoshis(5_000)), out _));
    }

    [Fact]
    public void Data_envelope_round_trips_protocol_and_fields()
    {
        var envelope = new DataEnvelope("map"u8, ["SET"u8.ToArray(), "app"u8.ToArray()]);
        Script script = envelope.ToScript();
        Assert.True(DataEnvelope.TryParse(script, out DataEnvelope? parsed));
        Assert.Equal("map"u8.ToArray(), parsed!.Protocol.ToArray());
        Assert.Equal("SET"u8.ToArray(), parsed.Fields[1]);
        Assert.Equal("app"u8.ToArray(), parsed.Fields[2]);
        Assert.False(DataEnvelope.TryParse(Script.P2pkhLock(new byte[20]), out _));
    }

    private static byte[] Scalar(int value)
    {
        var scalar = new byte[32];
        scalar[^1] = (byte)value;
        return scalar;
    }
}
