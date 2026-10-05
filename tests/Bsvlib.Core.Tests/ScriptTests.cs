using Bsvlib.Core;
using Bsvlib.Crypto;
using Xunit;

namespace Bsvlib.Core.Tests;

public class ScriptTests
{
    [Fact]
    public void Arithmetic_concatenation_and_conditionals_match_genesis_semantics()
    {
        AssertTop([0x56, 0x57, 0x95, 0x01, 0x2A, 0x9C], [0x01]);
        AssertTop([0x02, 0x61, 0x62, 0x02, 0x63, 0x64, 0x7E], "abcd"u8.ToArray());
        AssertTop([0x51, 0x63, 0x52, 0x67, 0x53, 0x68], [0x02]);
        AssertTop([0x00, 0x63, 0x52, 0x67, 0x53, 0x68], [0x03]);
        AssertTop([0x4F, 0x54, 0x80], [0x01, 0x00, 0x00, 0x80]);
        AssertTop([0x56, 0x51, 0x98], [0x0C]);
        Assert.False(ScriptInterpreter.Execute([0x51, 0x00, 0x96], out _, out ScriptError error));
        Assert.Equal(ScriptError.DivisionByZero, error);
        Assert.False(ScriptInterpreter.Execute([0x68], out _, out error));
        Assert.Equal(ScriptError.UnbalancedConditional, error);
    }

    [Fact]
    public void P2pkh_script_accepts_the_signature_from_the_transaction_builder()
    {
        Assert.True(PrivateKey.TryCreate(Scalar(1), out PrivateKey? key));
        Address address = Address.FromPublicKey(key!.GetPublicKey(), Network.Mainnet);
        Script locking = address.LockingScript;
        var builder = new TransactionBuilder()
            .AddInput(new OutPoint(TxId.Parse(new string('1', 64)), 0), new Satoshis(10_000), locking)
            .AddOutput(new Satoshis(9_000), locking);
        builder.SignP2pkh(0, key);
        Transaction tx = builder.Build();
        var checker = new TransactionSignatureChecker(tx, 0, new Satoshis(10_000));

        Assert.True(ScriptInterpreter.Verify(tx.Inputs[0].UnlockingScript, locking, checker, out ScriptError error));
        Assert.Equal(ScriptError.None, error);

        Assert.False(ScriptInterpreter.Verify(Script.Empty, locking, checker, out _));
    }

    private static void AssertTop(byte[] script, byte[] expected)
    {
        Assert.True(ScriptInterpreter.Execute(script, out byte[]? top, out ScriptError error), error.ToString());
        Assert.Equal(expected, top);
    }

    private static byte[] Scalar(int value)
    {
        var scalar = new byte[32];
        scalar[^1] = (byte)value;
        return scalar;
    }
}
