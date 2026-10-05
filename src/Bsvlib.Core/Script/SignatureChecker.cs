using Bsvlib.Crypto;

namespace Bsvlib.Core;

public interface ISignatureChecker
{
    bool CheckSignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> scriptCode);

    bool CheckLockTime(System.Numerics.BigInteger lockTime);

    bool CheckSequence(System.Numerics.BigInteger sequence);
}

public sealed class TransactionSignatureChecker : ISignatureChecker
{
    private const long LockTimeThreshold = 500_000_000;
    private const uint SequenceLocktimeDisableFlag = 1u << 31;
    private const uint SequenceLocktimeTypeFlag = 1u << 22;
    private const uint SequenceLocktimeMask = 0xFFFF;

    private readonly Transaction _transaction;
    private readonly int _input;
    private readonly Satoshis _amount;

    public TransactionSignatureChecker(Transaction transaction, int input, Satoshis amount)
    {
        _transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));
        if ((uint)input >= (uint)transaction.Inputs.Count)
            throw new ArgumentOutOfRangeException(nameof(input));
        _input = input;
        _amount = amount;
    }

    public bool CheckSignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> scriptCode)
    {
        if (signature.IsEmpty || !PublicKey.TryCreate(publicKey, out PublicKey? key))
            return false;

        byte hashType = signature[^1];
        byte[] digest = Sighash.Digest(_transaction, _input, new Script(scriptCode), _amount, (SighashType)hashType);
        return key!.VerifyDigest(digest, signature[..^1]);
    }

    public bool CheckLockTime(System.Numerics.BigInteger lockTime)
    {
        if (lockTime.Sign < 0 || lockTime > uint.MaxValue)
            return false;
        long requested = (long)lockTime;
        long txLock = _transaction.LockTime;
        if ((requested < LockTimeThreshold) != (txLock < LockTimeThreshold))
            return false;
        if (requested > txLock)
            return false;
        return _transaction.Inputs[_input].Sequence != 0xFFFF_FFFF;
    }

    public bool CheckSequence(System.Numerics.BigInteger sequence)
    {
        if (sequence.Sign < 0 || sequence > uint.MaxValue)
            return false;
        uint requested = (uint)sequence;
        if ((requested & SequenceLocktimeDisableFlag) != 0)
            return true;
        if (_transaction.Version < 2)
            return false;

        uint txSequence = _transaction.Inputs[_input].Sequence;
        if ((txSequence & SequenceLocktimeDisableFlag) != 0)
            return false;
        if ((requested & SequenceLocktimeTypeFlag) != (txSequence & SequenceLocktimeTypeFlag))
            return false;
        return (requested & SequenceLocktimeMask) <= (txSequence & SequenceLocktimeMask);
    }
}
