using Bsvlib.Core;
using Bsvlib.Protocols;
using Xunit;

namespace Bsvlib.Protocols.Tests;

public class ProtocolTests
{
    [Fact]
    public void Ord_envelope_round_trips_the_published_text_inscription()
    {
        var inscription = new Inscription("text/plain;charset=utf-8", "Hello, world!"u8);
        Script script = InscriptionEnvelope.Create(inscription);
        Assert.Equal(HelloWorld(), script.Bytes.ToArray());
        Assert.True(InscriptionEnvelope.TryParse(script, out InscriptionEnvelope? parsed));
        Assert.Equal("Hello, world!", parsed!.Inscription.BodyText);
        Assert.Equal("text/plain;charset=utf-8", parsed.Inscription.ContentType);
        Assert.Equal(0, parsed.LockingScript.Bytes.Length);
    }

    [Fact]
    public void Ord_envelope_keeps_a_locking_script_placed_in_front()
    {
        Script locking = Script.P2pkhLock(new byte[20]);
        Script script = InscriptionEnvelope.Create(new Inscription("text/plain", "one"u8), locking);
        Assert.True(InscriptionEnvelope.TryParse(script, out InscriptionEnvelope? parsed));
        Assert.Equal("one", parsed!.Inscription.BodyText);
        Assert.Equal(locking.Bytes.ToArray(), parsed.LockingScript.Bytes.ToArray());

        Script second = InscriptionEnvelope.Create(new Inscription("text/plain", "two"u8));
        var both = new byte[script.Bytes.Length + second.Bytes.Length];
        script.Bytes.CopyTo(both);
        second.Bytes.CopyTo(both.AsMemory(script.Bytes.Length));
        Assert.True(InscriptionEnvelope.TryParse(new Script(both), out InscriptionEnvelope? first));
        Assert.Equal("one", first!.Inscription.BodyText);
    }

    [Fact]
    public void Satoshis_flow_from_inputs_into_outputs_in_order()
    {
        IReadOnlyList<SatRange> inputs = OrdinalTracker.FromValues([1, 5_000]);
        OrdinalAssignment assignment = OrdinalTracker.Assign(inputs, [1, 4_900]);
        Assert.Equal(new SatRange(0, 1), Assert.Single(assignment.Outputs[0]));
        Assert.Equal(new SatRange(1, 4_901), Assert.Single(assignment.Outputs[1]));
        Assert.Equal(new SatRange(4_901, 5_001), Assert.Single(assignment.Fee));
        Assert.True(OrdinalTracker.TryLocate(assignment, 0, out int output));
        Assert.Equal(0, output);

        OrdinalAssignment split = OrdinalTracker.Assign([new SatRange(0, 5), new SatRange(10, 13)], [3, 4]);
        Assert.Equal([new SatRange(3, 5), new SatRange(10, 12)], split.Outputs[1]);
        Assert.False(OrdinalTracker.TryAssign([new SatRange(0, 1)], [2], out _));
    }

    [Fact]
    public void Bsv20_deploy_mint_and_transfer_round_trip()
    {
        Assert.True(Bsv20Deploy.TryParse("""{"p":"bsv-20","op":"deploy","tick":"ordi","max":"21000000","lim":"1000"}""", out Bsv20Deploy? deploy));
        Assert.Equal("ordi", deploy!.Ticker);
        Assert.Equal("21000000", deploy.MaxSupply);
        Assert.Equal(Bsv20Deploy.ContentType, deploy.ToInscription().ContentType);
        Assert.True(Bsv20Deploy.TryParse(deploy.ToJson(), out Bsv20Deploy? again));
        Assert.Equal("ordi", again!.Ticker);
        Assert.Equal("1000", again.MintLimit);

        Assert.True(Bsv20Mint.TryParse("""{"p":"bsv-20","op":"mint","tick":"ordi","amt":"1000"}""", out Bsv20Mint? mint));
        Assert.Equal("1000", mint!.Amount);
        Assert.True(Bsv20Transfer.TryParse("""{"p":"bsv-20","op":"transfer","tick":"ordi","amt":"100"}""", out Bsv20Transfer? transfer));
        Assert.Equal("ordi", transfer!.Ticker);
        Assert.True(Bsv20Transfer.TryParse(transfer.ToJson(), out _));
        Assert.False(Bsv20Mint.TryParse("""{"p":"bsv-20","op":"mint","tick":"no","amt":"1"}""", out _));
    }

    [Fact]
    public void Map_b_and_aip_read_the_op_return_fields()
    {
        var map = new MapRecord("SET", [new KeyValuePair<string, string>("app", "ord-demo"), new KeyValuePair<string, string>("type", "post")]);
        Assert.True(MapRecord.TryParse(map.ToEnvelope().ToScript(), out MapRecord? parsedMap));
        Assert.Equal("post", parsedMap!.Attributes[1].Value);

        var file = new BinaryContent("hello"u8.ToArray(), "text/plain", "utf-8", "hello.txt");
        Assert.True(BinaryContent.TryParse(file.ToEnvelope().ToScript(), out BinaryContent? parsedFile));
        Assert.Equal("hello.txt", parsedFile!.FileName);
        Assert.Equal("hello"u8.ToArray(), parsedFile.Data.ToArray());

        var signature = new AuthorIdentity("BITCOIN_ECDSA", "1Address", "c2ln", "0");
        Assert.True(AuthorIdentity.TryParse(signature.ToEnvelope().ToScript(), out AuthorIdentity? parsedSignature));
        Assert.Equal("c2ln", parsedSignature!.Signature);
    }

    private static byte[] HelloWorld()
    {
        byte[] type = "text/plain;charset=utf-8"u8.ToArray();
        byte[] body = "Hello, world!"u8.ToArray();
        var script = new byte[2 + 4 + 1 + 1 + type.Length + 1 + 1 + body.Length + 1];
        script[0] = 0x00;
        script[1] = 0x63;
        script[2] = 0x03;
        "ord"u8.CopyTo(script.AsSpan(3));
        script[6] = 0x51;
        script[7] = (byte)type.Length;
        type.CopyTo(script.AsSpan(8));
        int offset = 8 + type.Length;
        script[offset++] = 0x00;
        script[offset++] = (byte)body.Length;
        body.CopyTo(script.AsSpan(offset));
        script[^1] = 0x68;
        return script;
    }
}
