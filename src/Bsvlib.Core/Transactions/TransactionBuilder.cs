using Bsvlib.Crypto;

namespace Bsvlib.Core;

public sealed class TransactionBuilder
{
    private readonly List<InputDraft> _inputs = [];
    private readonly List<TxOutput> _outputs = [];
    private int _version = 1;
    private uint _lockTime;

    public TransactionBuilder SetVersion(int version)
    {
        _version = version;
        return this;
    }

    public TransactionBuilder SetLockTime(uint lockTime)
    {
        _lockTime = lockTime;
        return this;
    }

    public TransactionBuilder AddInput(OutPoint previousOutput, Satoshis previousValue, Script lockingScript, uint sequence = 0xFFFF_FFFF)
    {
        ArgumentNullException.ThrowIfNull(lockingScript);
        _inputs.Add(new InputDraft(previousOutput, previousValue, lockingScript, sequence));
        return this;
    }

    public TransactionBuilder AddOutput(Satoshis value, Script lockingScript)
    {
        _outputs.Add(new TxOutput(value, lockingScript));
        return this;
    }

    public TransactionBuilder SignP2pkh(int index, PrivateKey key, SighashType sighash = SighashType.All | SighashType.ForkId)
    {
        ArgumentNullException.ThrowIfNull(key);
        if ((uint)index >= (uint)_inputs.Count)
            throw new ArgumentOutOfRangeException(nameof(index));

        InputDraft draft = _inputs[index];
        Span<byte> expected = stackalloc byte[20];
        if (!draft.LockingScript.TryGetP2pkhHash(expected))
            throw new InvalidOperationException("Previous output is not a P2PKH script.");

        PublicKey compressed = key.GetPublicKey(compressed: true);
        PublicKey uncompressed = key.GetPublicKey(compressed: false);
        PublicKey chosen = Match(compressed, expected) ? compressed
            : Match(uncompressed, expected) ? uncompressed
            : throw new InvalidOperationException("Private key does not match the P2PKH hash.");

        Transaction unsigned = Snapshot();
        byte[] digest = Sighash.Digest(unsigned, index, draft.LockingScript, draft.PreviousValue, sighash);
        byte[] der = key.SignDigestDer(digest);
        var signature = new byte[der.Length + 1];
        der.CopyTo(signature);
        signature[^1] = (byte)sighash;
        draft.UnlockingScript = Script.P2pkhUnlock(signature, chosen.ToBytes());
        return this;
    }

    /// <summary>
    /// 按字节费率把剩余金额找零。未签名的输入按 P2PKH 解锁脚本估算体积。
    /// 找零低于 <paramref name="dustLimit"/> 时不再单独生成输出。
    /// </summary>
    public TransactionBuilder PayChange(Script changeScript, long satoshisPerByte, long dustLimit = 1)
    {
        ArgumentNullException.ThrowIfNull(changeScript);
        if (satoshisPerByte < 0)
            throw new ArgumentOutOfRangeException(nameof(satoshisPerByte));
        if (dustLimit < 0)
            throw new ArgumentOutOfRangeException(nameof(dustLimit));

        long inputTotal = 0;
        foreach (InputDraft input in _inputs)
            inputTotal = checked(inputTotal + input.PreviousValue.Value);
        long outputTotal = 0;
        foreach (TxOutput output in _outputs)
            outputTotal = checked(outputTotal + output.Value.Value);

        int signedSize = SignedSizeEstimate();
        long remainder = inputTotal - outputTotal;
        if (remainder < checked(signedSize * satoshisPerByte))
            throw new InvalidOperationException("Inputs do not cover the outputs and fee.");

        int changeScriptLength = changeScript.Bytes.Length;
        int changeSize = 8 + VarInt.GetSize((ulong)changeScriptLength) + changeScriptLength;
        long change = remainder - checked((signedSize + changeSize) * satoshisPerByte);
        if (change >= dustLimit)
            _outputs.Add(new TxOutput(new Satoshis(change), changeScript));
        return this;
    }

    private int SignedSizeEstimate()
    {
        int size = Build().GetSerializedLength();
        foreach (InputDraft input in _inputs)
        {
            if (input.UnlockingScript.Bytes.Length == 0)
                size += P2pkhUnlockBodyLength;
        }

        return size;
    }

    private const int P2pkhUnlockBodyLength = 108;

    public Transaction Build()
    {
        var inputs = new TxInput[_inputs.Count];
        for (int i = 0; i < inputs.Length; i++)
        {
            InputDraft draft = _inputs[i];
            inputs[i] = new TxInput(draft.PreviousOutput, draft.UnlockingScript, draft.Sequence);
        }

        return new Transaction(_version, inputs, _outputs, _lockTime);
    }

    private Transaction Snapshot() => Build();

    private static bool Match(PublicKey key, ReadOnlySpan<byte> hash160)
    {
        Span<byte> actual = stackalloc byte[20];
        Hash160.Write(key.ToBytes(), actual);
        return actual.SequenceEqual(hash160);
    }

    private sealed class InputDraft
    {
        public InputDraft(OutPoint previousOutput, Satoshis previousValue, Script lockingScript, uint sequence)
        {
            PreviousOutput = previousOutput;
            PreviousValue = previousValue;
            LockingScript = lockingScript;
            Sequence = sequence;
            UnlockingScript = Script.Empty;
        }

        public OutPoint PreviousOutput { get; }

        public Satoshis PreviousValue { get; }

        public Script LockingScript { get; }

        public uint Sequence { get; }

        public Script UnlockingScript { get; set; }
    }
}
