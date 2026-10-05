using System.Buffers.Binary;
using Bsvlib.Core;
using Bsvlib.Crypto;
using Xunit;

namespace Bsvlib.Core.Tests;

file static class TestKeys
{
    public static byte[] Scalar(int value)
    {
        var scalar = new byte[32];
        scalar[^1] = (byte)value;
        return scalar;
    }
}

public class EncodingTests
{
    [Theory]
    [InlineData(0ul, 1)]
    [InlineData(0xFCul, 1)]
    [InlineData(0xFDul, 3)]
    [InlineData(0xFFFFul, 3)]
    [InlineData(0x10000ul, 5)]
    [InlineData(0x1_0000_0000ul, 9)]
    public void VarInt_writes_the_shortest_form(ulong value, int size)
    {
        var buffer = new byte[9];
        Assert.Equal(size, VarInt.GetSize(value));
        Assert.Equal(size, VarInt.Write(buffer, value));
        Assert.True(VarInt.TryRead(buffer, out ulong read, out int consumed));
        Assert.Equal(value, read);
        Assert.Equal(size, consumed);
    }

    [Fact]
    public void Satoshis_reject_negative_and_above_max_supply()
    {
        Assert.False(Satoshis.TryCreate(-1, out _));
        Assert.False(Satoshis.TryCreate(Satoshis.MaxValue + 1, out _));
        Assert.Equal(50_000L, new Satoshis(50_000).Value);
        Assert.Throws<OverflowException>(() => new Satoshis(Satoshis.MaxValue).Add(new Satoshis(1)));
        Assert.Throws<OverflowException>(() => new Satoshis(1).Subtract(new Satoshis(2)));
    }

    [Fact]
    public void TxId_display_is_the_reverse_of_the_wire_bytes()
    {
        byte[] wire = new byte[32];
        wire[0] = 0x3b;
        wire[31] = 0x4a;
        TxId id = TxId.FromWire(wire);
        Assert.Equal("4a0000000000000000000000000000000000000000000000000000000000003b", id.ToString());
        Assert.Equal(id, TxId.Parse(id.ToString().ToUpperInvariant()));
        Assert.False(TxId.TryParse("zz", out _));
    }
}

public class TransactionTests
{
    private const string GenesisCoinbase =
        "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000";

    private const string GenesisHeader =
        "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c";

    [Fact]
    public void Genesis_coinbase_parses_and_keeps_its_txid()
    {
        byte[] raw = Convert.FromHexString(GenesisCoinbase);
        Assert.True(Transaction.TryRead(raw, out Transaction? tx, out int read));
        Assert.Equal(raw.Length, read);
        Assert.Equal("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b", tx!.Id.ToString());
        Assert.True(tx.Inputs[0].PreviousOutput.IsCoinbase);
        Assert.Equal(5_000_000_000L, tx.Outputs[0].Value.Value);
        Assert.Equal(raw, tx.ToBytes());
        Assert.False(Transaction.TryRead(raw.AsSpan(0, 10), out _, out _));
    }

    [Fact]
    public void Genesis_header_hashes_to_the_published_block_id()
    {
        byte[] raw = Convert.FromHexString(GenesisHeader);
        Assert.True(BlockHeader.TryRead(raw, out BlockHeader? header));
        Assert.Equal("000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f", header!.Hash.ToString());
        Assert.Equal(raw, header.ToBytes());
        Assert.Equal(header.MerkleRoot, TxId.Parse("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));
    }
}

public class AddressTests
{
    [Fact]
    public void Mainnet_p2pkh_address_matches_the_published_vector()
    {
        byte[] hash = Convert.FromHexString("f54a5851e9372b87810a8e60cdd2e7cfd80b6e31");
        Address address = Address.P2pkh(hash, Network.Mainnet);
        Assert.Equal("1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs", address.ToString());
        Assert.True(Address.TryParse(address.ToString(), Network.Mainnet, out Address? parsed));
        Assert.Equal(AddressKind.P2pkh, parsed!.Kind);
        Assert.Equal(address.LockingScript, parsed.LockingScript);
        Assert.False(Address.TryParse(address.ToString(), Network.Testnet, out _));
    }

    [Fact]
    public void Private_key_one_has_the_published_address_and_wif()
    {
        Assert.True(PrivateKey.TryCreate(TestKeys.Scalar(1), out PrivateKey? key));
        Assert.Equal("1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH", Address.FromPublicKey(key!.GetPublicKey(), Network.Mainnet).ToString());
        Assert.Equal("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", Wif.Encode(key, Network.Mainnet));
        Assert.True(Wif.TryDecode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", Network.Mainnet, out PrivateKey? decoded, out bool compressed));
        Assert.True(compressed);
        Assert.Equal(key.ToBytes(), decoded!.ToBytes());
        Assert.False(Wif.TryDecode("KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn", Network.Testnet, out _, out _));
    }

    [Fact]
    public void Code_separators_are_removed_only_when_they_are_opcodes()
    {
        Script script = new([0x51, 0xAB, 0x52, 0x01, 0xAB]);
        Assert.Equal(new byte[] { 0x51, 0x52, 0x01, 0xAB }, script.WithoutCodeSeparators().Bytes.ToArray());
    }
}

public class SighashTests
{
    [Fact]
    public void ForkId_preimage_follows_the_bip143_layout()
    {
        Script locking = Script.P2pkhLock(new byte[20]);
        TxId prev = TxId.Parse("1111111111111111111111111111111111111111111111111111111111111111");
        var previous = new OutPoint(prev, 7);
        var value = new Satoshis(50_000);
        var paid = new Satoshis(40_000);
        const uint sequence = 0xFFFF_FFFE;
        Transaction tx = new TransactionBuilder()
            .SetVersion(2)
            .SetLockTime(9)
            .AddInput(previous, value, locking, sequence)
            .AddOutput(paid, locking)
            .Build();

        Assert.True(Sighash.TryGetPreimage(tx, 0, locking, value, SighashType.All | SighashType.ForkId, out byte[] preimage));
        Assert.Equal(ManualForkIdPreimage(tx, locking, value, sequence, previous), preimage);
        Assert.Equal(Hash256.Compute(preimage), Sighash.Digest(tx, 0, locking, value, SighashType.All | SighashType.ForkId));
    }

    [Fact]
    public void Chronicle_preimage_is_the_original_transaction_digest()
    {
        Script locking = Script.P2pkhLock(Enumerable.Repeat((byte)0x22, 20).ToArray());
        var previous = new OutPoint(TxId.Parse("2222222222222222222222222222222222222222222222222222222222222222"), 1);
        Transaction tx = new TransactionBuilder()
            .AddInput(previous, new Satoshis(1000), locking, 0xFFFFFFF0)
            .AddOutput(new Satoshis(900), locking)
            .Build();

        Assert.True(Sighash.TryGetPreimage(tx, 0, locking, new Satoshis(1000), SighashType.All | SighashType.Chronicle, out byte[] preimage));
        Assert.Equal(ManualOriginalPreimage(previous, locking, 0xFFFFFFF0, new Satoshis(900), SighashType.All | SighashType.Chronicle), preimage);
        Assert.NotEqual(
            Sighash.Digest(tx, 0, locking, new Satoshis(1000), SighashType.All | SighashType.ForkId),
            Sighash.Digest(tx, 0, locking, new Satoshis(1000), SighashType.All | SighashType.Chronicle));
    }

    [Fact]
    public void AnyoneCanPay_zeroes_the_prevout_hash_and_single_without_outputs_returns_uint256_one()
    {
        Script locking = Script.P2pkhLock(new byte[20]);
        Transaction tx = new TransactionBuilder()
            .AddInput(new OutPoint(TxId.Parse("3333333333333333333333333333333333333333333333333333333333333333"), 0), new Satoshis(1), locking)
            .AddOutput(new Satoshis(1), locking)
            .Build();

        Assert.True(Sighash.TryGetPreimage(tx, 0, locking, new Satoshis(1), SighashType.All | SighashType.ForkId | SighashType.AnyoneCanPay, out byte[] preimage));
        Assert.Equal(new byte[32], preimage.AsSpan(4, 32).ToArray());

        Transaction noOutputs = new Transaction(1, tx.Inputs, [], 0);
        Assert.False(Sighash.TryGetPreimage(noOutputs, 0, locking, new Satoshis(1), SighashType.Single | SighashType.Chronicle, out _));
        byte[] digest = Sighash.Digest(noOutputs, 0, locking, new Satoshis(1), SighashType.Single | SighashType.Chronicle);
        Assert.Equal(1, digest[0]);
        Assert.All(digest.AsSpan(1).ToArray(), b => Assert.Equal(0, b));
    }

    [Fact]
    public void Signed_p2pkh_input_verifies_and_breaks_when_an_output_changes()
    {
        Assert.True(PrivateKey.TryCreate(TestKeys.Scalar(1), out PrivateKey? key));
        Address address = Address.FromPublicKey(key!.GetPublicKey(), Network.Mainnet);
        var builder = new TransactionBuilder()
            .AddInput(new OutPoint(TxId.Parse("4444444444444444444444444444444444444444444444444444444444444444"), 3), new Satoshis(1000), address.LockingScript)
            .AddOutput(new Satoshis(900), address.LockingScript);
        builder.SignP2pkh(0, key);
        Transaction tx = builder.Build();

        ReadOnlySpan<byte> script = tx.Inputs[0].UnlockingScript.Bytes.Span;
        int push = script[0];
        ReadOnlySpan<byte> signature = script.Slice(1, push);
        Assert.Equal(0x41, signature[^1]);
        byte[] digest = Sighash.Digest(tx, 0, address.LockingScript, new Satoshis(1000), SighashType.All | SighashType.ForkId);
        Assert.True(key.GetPublicKey().VerifyDigest(digest, signature[..^1]));

        Transaction changed = new Transaction(tx.Version, tx.Inputs, [new TxOutput(new Satoshis(800), address.LockingScript)], tx.LockTime);
        byte[] changedDigest = Sighash.Digest(changed, 0, address.LockingScript, new Satoshis(1000), SighashType.All | SighashType.ForkId);
        Assert.False(key.GetPublicKey().VerifyDigest(changedDigest, signature[..^1]));
    }

    private static byte[] ManualForkIdPreimage(Transaction tx, Script locking, Satoshis value, uint sequence, OutPoint previous)
    {
        Span<byte> outpoint = stackalloc byte[36];
        previous.Write(outpoint);
        Span<byte> hashPrevouts = stackalloc byte[32];
        Hash256.Write(outpoint, hashPrevouts);
        Span<byte> sequenceBytes = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(sequenceBytes, sequence);
        Span<byte> hashSequence = stackalloc byte[32];
        Hash256.Write(sequenceBytes, hashSequence);
        byte[] output = new byte[tx.Outputs[0].GetSerializedLength()];
        tx.Outputs[0].Write(output);
        Span<byte> hashOutputs = stackalloc byte[32];
        Hash256.Write(output, hashOutputs);

        var preimage = new byte[4 + 32 + 32 + 36 + 1 + locking.Bytes.Length + 8 + 4 + 32 + 4 + 4];
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(preimage, 2);
        offset = 4;
        hashPrevouts.CopyTo(preimage.AsSpan(offset));
        offset += 32;
        hashSequence.CopyTo(preimage.AsSpan(offset));
        offset += 32;
        outpoint.CopyTo(preimage.AsSpan(offset));
        offset += 36;
        preimage[offset++] = (byte)locking.Bytes.Length;
        locking.Bytes.Span.CopyTo(preimage.AsSpan(offset));
        offset += locking.Bytes.Length;
        BinaryPrimitives.WriteInt64LittleEndian(preimage.AsSpan(offset), value.Value);
        offset += 8;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), sequence);
        offset += 4;
        hashOutputs.CopyTo(preimage.AsSpan(offset));
        offset += 32;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), 9);
        offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), (uint)(SighashType.All | SighashType.ForkId));
        return preimage;
    }

    private static byte[] ManualOriginalPreimage(OutPoint previous, Script locking, uint sequence, Satoshis paid, SighashType sighash)
    {
        int scriptLength = locking.Bytes.Length;
        int outputLength = 8 + 1 + scriptLength;
        var preimage = new byte[4 + 1 + 36 + 1 + scriptLength + 4 + 1 + outputLength + 4 + 4];
        int offset = 0;
        BinaryPrimitives.WriteInt32LittleEndian(preimage, 1);
        offset = 4;
        preimage[offset++] = 1;
        previous.Write(preimage.AsSpan(offset));
        offset += 36;
        preimage[offset++] = (byte)scriptLength;
        locking.Bytes.Span.CopyTo(preimage.AsSpan(offset));
        offset += scriptLength;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), sequence);
        offset += 4;
        preimage[offset++] = 1;
        BinaryPrimitives.WriteInt64LittleEndian(preimage.AsSpan(offset), paid.Value);
        offset += 8;
        preimage[offset++] = (byte)scriptLength;
        locking.Bytes.Span.CopyTo(preimage.AsSpan(offset));
        offset += scriptLength;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), 0);
        offset += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(preimage.AsSpan(offset), (uint)sighash);
        return preimage;
    }
}
