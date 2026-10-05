using System.Numerics;
using System.Security.Cryptography;
using Bsvlib.Crypto;

namespace Bsvlib.Core;

public enum ScriptError
{
    None,
    BadOpcode,
    UnbalancedConditional,
    InvalidStackOperation,
    InvalidNumber,
    VerifyFailed,
    Return,
    SignatureFailed,
    LockTimeFailed,
    SequenceFailed,
    EvalFalse,
    PushOnly,
    DivisionByZero,
}

public static class ScriptInterpreter
{
    private const int Op0 = 0x00;
    private const int OpPushData1 = 0x4C;
    private const int OpPushData2 = 0x4D;
    private const int OpPushData4 = 0x4E;
    private const int Op1Negate = 0x4F;
    private const int OpReserved = 0x50;
    private const int Op1 = 0x51;
    private const int Op16 = 0x60;
    private const int OpNop = 0x61;
    private const int OpIf = 0x63;
    private const int OpNotIf = 0x64;
    private const int OpElse = 0x67;
    private const int OpEndIf = 0x68;
    private const int OpVerify = 0x69;
    private const int OpReturn = 0x6A;
    private const int OpToAltStack = 0x6B;
    private const int OpFromAltStack = 0x6C;
    private const int Op2Drop = 0x6D;
    private const int Op2Dup = 0x6E;
    private const int Op3Dup = 0x6F;
    private const int Op2Over = 0x70;
    private const int Op2Rot = 0x71;
    private const int Op2Swap = 0x72;
    private const int OpIfDup = 0x73;
    private const int OpDepth = 0x74;
    private const int OpDrop = 0x75;
    private const int OpDup = 0x76;
    private const int OpNip = 0x77;
    private const int OpOver = 0x78;
    private const int OpPick = 0x79;
    private const int OpRoll = 0x7A;
    private const int OpRot = 0x7B;
    private const int OpSwap = 0x7C;
    private const int OpTuck = 0x7D;
    private const int OpCat = 0x7E;
    private const int OpSplit = 0x7F;
    private const int OpNum2Bin = 0x80;
    private const int OpBin2Num = 0x81;
    private const int OpSize = 0x82;
    private const int OpInvert = 0x83;
    private const int OpAnd = 0x84;
    private const int OpOr = 0x85;
    private const int OpXor = 0x86;
    private const int OpEqual = 0x87;
    private const int OpEqualVerify = 0x88;
    private const int Op1Add = 0x8B;
    private const int Op1Sub = 0x8C;
    private const int Op2Mul = 0x8D;
    private const int Op2Div = 0x8E;
    private const int OpNegate = 0x8F;
    private const int OpAbs = 0x90;
    private const int OpNot = 0x91;
    private const int Op0NotEqual = 0x92;
    private const int OpAdd = 0x93;
    private const int OpSub = 0x94;
    private const int OpMul = 0x95;
    private const int OpDiv = 0x96;
    private const int OpMod = 0x97;
    private const int OpLShift = 0x98;
    private const int OpRShift = 0x99;
    private const int OpBoolAnd = 0x9A;
    private const int OpBoolOr = 0x9B;
    private const int OpNumEqual = 0x9C;
    private const int OpNumEqualVerify = 0x9D;
    private const int OpNumNotEqual = 0x9E;
    private const int OpLessThan = 0x9F;
    private const int OpGreaterThan = 0xA0;
    private const int OpLessThanOrEqual = 0xA1;
    private const int OpGreaterThanOrEqual = 0xA2;
    private const int OpMin = 0xA3;
    private const int OpMax = 0xA4;
    private const int OpWithin = 0xA5;
    private const int OpRipemd160 = 0xA6;
    private const int OpSha1 = 0xA7;
    private const int OpSha256 = 0xA8;
    private const int OpHash160 = 0xA9;
    private const int OpHash256 = 0xAA;
    private const int OpCodeSeparator = 0xAB;
    private const int OpCheckSig = 0xAC;
    private const int OpCheckSigVerify = 0xAD;
    private const int OpCheckMultiSig = 0xAE;
    private const int OpCheckMultiSigVerify = 0xAF;
    private const int OpNop1 = 0xB0;
    private const int OpCheckLockTimeVerify = 0xB1;
    private const int OpCheckSequenceVerify = 0xB2;

    public static bool Verify(Script unlocking, Script locking, ISignatureChecker checker, out ScriptError error)
    {
        ArgumentNullException.ThrowIfNull(unlocking);
        ArgumentNullException.ThrowIfNull(locking);
        ArgumentNullException.ThrowIfNull(checker);
        if (!IsPushOnly(unlocking.Bytes.Span))
        {
            error = ScriptError.PushOnly;
            return false;
        }

        var stack = new List<byte[]>();
        if (!Execute(unlocking.Bytes.Span, stack, checker, out error))
            return false;
        if (!Execute(locking.Bytes.Span, stack, checker, out error))
            return false;
        if (stack.Count == 0 || !IsTrue(stack[^1]))
        {
            error = ScriptError.EvalFalse;
            return false;
        }

        error = ScriptError.None;
        return true;
    }

    public static bool Execute(ReadOnlySpan<byte> script, out byte[]? top, out ScriptError error)
    {
        var stack = new List<byte[]>();
        if (!Execute(script, stack, new DisabledChecker(), out error))
        {
            top = null;
            return false;
        }

        top = stack.Count == 0 ? null : stack[^1];
        error = ScriptError.None;
        return true;
    }

    private static bool Execute(ReadOnlySpan<byte> script, List<byte[]> stack, ISignatureChecker checker, out ScriptError error)
    {
        var alt = new List<byte[]>();
        var conditions = new Stack<bool>();
        int pc = 0;
        int codeSeparator = 0;
        while (pc < script.Length)
        {
            if (!TryReadInstruction(script, ref pc, out int opcode, out ReadOnlySpan<byte> data))
            {
                error = ScriptError.BadOpcode;
                return false;
            }

            if (opcode is OpIf or OpNotIf)
            {
                bool value = false;
                if (Executing(conditions))
                {
                    if (stack.Count == 0 || !IsMinimalBoolean(stack[^1]))
                    {
                        error = ScriptError.InvalidStackOperation;
                        return false;
                    }

                    value = IsTrue(Pop(stack));
                    if (opcode == OpNotIf)
                        value = !value;
                }

                conditions.Push(value);
                continue;
            }

            if (opcode == OpElse)
            {
                if (conditions.Count == 0)
                {
                    error = ScriptError.UnbalancedConditional;
                    return false;
                }

                conditions.Push(!conditions.Pop());
                continue;
            }

            if (opcode == OpEndIf)
            {
                if (conditions.Count == 0)
                {
                    error = ScriptError.UnbalancedConditional;
                    return false;
                }

                conditions.Pop();
                continue;
            }

            if (!Executing(conditions))
                continue;

            if (opcode == OpCodeSeparator)
            {
                codeSeparator = pc;
                continue;
            }

            if (!Step(opcode, data, script[codeSeparator..], stack, alt, checker, out error))
                return false;
        }

        if (conditions.Count != 0)
        {
            error = ScriptError.UnbalancedConditional;
            return false;
        }

        error = ScriptError.None;
        return true;
    }

    private static bool Step(int opcode, ReadOnlySpan<byte> data, ReadOnlySpan<byte> scriptCode, List<byte[]> stack, List<byte[]> alt, ISignatureChecker checker, out ScriptError error)
    {
        error = ScriptError.None;
        if (opcode <= OpPushData4)
        {
            if (!IsMinimalPush(opcode, data))
            {
                error = ScriptError.BadOpcode;
                return false;
            }

            Push(stack, data.ToArray());
            return true;
        }

        if (opcode == Op1Negate)
        {
            Push(stack, [0x81]);
            return true;
        }

        if (opcode is >= Op1 and <= Op16)
        {
            Push(stack, [(byte)(opcode - Op1 + 1)]);
            return true;
        }

        switch (opcode)
        {
            case OpNop:
            case OpNop1:
            case >= 0xB3 and <= 0xB9:
                return true;
            case OpReserved:
            case 0x62:
            case 0x65:
            case 0x66:
            case 0x89:
            case 0x8A:
                error = ScriptError.BadOpcode;
                return false;
            case OpVerify:
                return PopBool(stack, out error) && True(ref error);
            case OpReturn:
                error = ScriptError.Return;
                return false;
            case OpToAltStack:
                if (!Pop(stack, out byte[] moved, out error))
                    return false;
                Push(alt, moved);
                return true;
            case OpFromAltStack:
                if (!Pop(alt, out byte[] restored, out error))
                    return false;
                Push(stack, restored);
                return true;
            case OpDrop:
                return Pop(stack, out _, out error);
            case Op2Drop:
                return Pop(stack, out _, out error) && Pop(stack, out _, out error);
            case OpDup:
                return Peek(stack, 0, out byte[] dup, out error) && PushCopy(stack, dup);
            case Op2Dup:
                return Peek(stack, 1, out byte[] a, out error) && Peek(stack, 0, out byte[] b, out _) && PushCopy(stack, a) && PushCopy(stack, b);
            case Op3Dup:
                return Peek(stack, 2, out byte[] x, out error) && Peek(stack, 1, out byte[] y, out _) && Peek(stack, 0, out byte[] z, out _)
                    && PushCopy(stack, x) && PushCopy(stack, y) && PushCopy(stack, z);
            case OpNip:
                return Remove(stack, 1, out error);
            case OpOver:
                return Peek(stack, 1, out byte[] over, out error) && PushCopy(stack, over);
            case OpSwap:
                return Swap(stack, 0, 1, out error);
            case OpRot:
                return Rot(stack, out error);
            case OpTuck:
                return Peek(stack, 0, out byte[] top, out error) && InsertCopy(stack, 2, top);
            case Op2Over:
                return Peek(stack, 3, out byte[] o1, out error) && Peek(stack, 2, out byte[] o2, out _) && PushCopy(stack, o1) && PushCopy(stack, o2);
            case Op2Swap:
                return Swap(stack, 0, 2, out error) && Swap(stack, 1, 3, out error);
            case Op2Rot:
                return Move(stack, 5, out error) && Move(stack, 5, out error);
            case OpIfDup:
                return Peek(stack, 0, out byte[] item, out error) && (!IsTrue(item) || PushCopy(stack, item));
            case OpDepth:
                Push(stack, ScriptNum.Encode(stack.Count));
                return true;
            case OpSize:
                return Peek(stack, 0, out byte[] sized, out error) && Push(stack, ScriptNum.Encode(sized.Length));
            case OpPick:
                return PopNum(stack, out BigInteger pick, out error) && pick >= 0 && pick < stack.Count && Peek(stack, (int)pick, out byte[] picked, out error) && PushCopy(stack, picked);
            case OpRoll:
                return PopNum(stack, out BigInteger roll, out error) && roll >= 0 && roll < stack.Count && Move(stack, (int)roll, out error);
            case OpCat:
                return Binary(stack, (left, right) => [.. left, .. right], out error);
            case OpSplit:
                return Split(stack, out error);
            case OpNum2Bin:
                return Num2Bin(stack, out error);
            case OpBin2Num:
                return Pop(stack, out byte[] raw, out error) && ScriptNum.TryDecode(raw, out BigInteger decoded, requireMinimal: false) && Push(stack, ScriptNum.Encode(decoded));
            case OpInvert:
                return MutateTop(stack, bytes => { for (int i = 0; i < bytes.Length; i++) bytes[i] = (byte)~bytes[i]; }, out error);
            case OpAnd:
                return Bitwise(stack, (left, right) => (byte)(left & right), out error);
            case OpOr:
                return Bitwise(stack, (left, right) => (byte)(left | right), out error);
            case OpXor:
                return Bitwise(stack, (left, right) => (byte)(left ^ right), out error);
            case OpEqual:
                return Pop(stack, out byte[] rightEq, out error) && Pop(stack, out byte[] leftEq, out error) && PushBool(stack, leftEq.AsSpan().SequenceEqual(rightEq));
            case OpEqualVerify:
                return Pop(stack, out byte[] rightV, out error) && Pop(stack, out byte[] leftV, out error) && leftV.AsSpan().SequenceEqual(rightV) ? true : Fail(ScriptError.VerifyFailed, out error);
            case Op1Add:
                return Unary(stack, value => value + 1, out error);
            case Op1Sub:
                return Unary(stack, value => value - 1, out error);
            case Op2Mul:
                return Unary(stack, value => value * 2, out error);
            case Op2Div:
                return Unary(stack, value => value / 2, out error);
            case OpNegate:
                return Unary(stack, value => -value, out error);
            case OpAbs:
                return Unary(stack, BigInteger.Abs, out error);
            case OpNot:
                return Unary(stack, value => value.IsZero ? 1 : 0, out error);
            case Op0NotEqual:
                return Unary(stack, value => value.IsZero ? 0 : 1, out error);
            case OpAdd:
                return BinaryNum(stack, (left, right) => left + right, out error);
            case OpSub:
                return BinaryNum(stack, (left, right) => left - right, out error);
            case OpMul:
                return BinaryNum(stack, (left, right) => left * right, out error);
            case OpDiv:
                return Divide(stack, modulo: false, out error);
            case OpMod:
                return Divide(stack, modulo: true, out error);
            case OpLShift:
            case OpRShift:
                return Shift(stack, opcode == OpLShift, out error);
            case OpBoolAnd:
                return BinaryNum(stack, (left, right) => !left.IsZero && !right.IsZero ? 1 : 0, out error);
            case OpBoolOr:
                return BinaryNum(stack, (left, right) => !left.IsZero || !right.IsZero ? 1 : 0, out error);
            case OpNumEqual:
                return BinaryNum(stack, (left, right) => left == right ? 1 : 0, out error);
            case OpNumEqualVerify:
                return BinaryNum(stack, (left, right) => left == right ? 1 : 0, out error) && PopBool(stack, out error);
            case OpNumNotEqual:
                return BinaryNum(stack, (left, right) => left != right ? 1 : 0, out error);
            case OpLessThan:
                return BinaryNum(stack, (left, right) => left < right ? 1 : 0, out error);
            case OpGreaterThan:
                return BinaryNum(stack, (left, right) => left > right ? 1 : 0, out error);
            case OpLessThanOrEqual:
                return BinaryNum(stack, (left, right) => left <= right ? 1 : 0, out error);
            case OpGreaterThanOrEqual:
                return BinaryNum(stack, (left, right) => left >= right ? 1 : 0, out error);
            case OpMin:
                return BinaryNum(stack, BigInteger.Min, out error);
            case OpMax:
                return BinaryNum(stack, BigInteger.Max, out error);
            case OpWithin:
                return Within(stack, out error);
            case OpRipemd160:
                return Hash(stack, Ripemd160.Compute, out error);
            case OpSha1:
                return Hash(stack, SHA1.HashData, out error);
            case OpSha256:
                return Hash(stack, SHA256.HashData, out error);
            case OpHash160:
                return Hash(stack, Hash160.Compute, out error);
            case OpHash256:
                return Hash(stack, Hash256.Compute, out error);
            case OpCheckSig:
            case OpCheckSigVerify:
                return CheckSig(stack, scriptCode, checker, opcode == OpCheckSigVerify, out error);
            case OpCheckMultiSig:
            case OpCheckMultiSigVerify:
                return CheckMultiSig(stack, scriptCode, checker, opcode == OpCheckMultiSigVerify, out error);
            case OpCheckLockTimeVerify:
                return Peek(stack, 0, out byte[] lockBytes, out error)
                    && ScriptNum.TryDecode(lockBytes, out BigInteger lockTime)
                    && checker.CheckLockTime(lockTime) ? true : Fail(error == ScriptError.None ? ScriptError.LockTimeFailed : error, out error);
            case OpCheckSequenceVerify:
                return Peek(stack, 0, out byte[] sequenceBytes, out error)
                    && ScriptNum.TryDecode(sequenceBytes, out BigInteger sequence)
                    && checker.CheckSequence(sequence) ? true : Fail(error == ScriptError.None ? ScriptError.SequenceFailed : error, out error);
            default:
                error = ScriptError.BadOpcode;
                return false;
        }
    }

    private static bool CheckSig(List<byte[]> stack, ReadOnlySpan<byte> scriptCode, ISignatureChecker checker, bool verify, out ScriptError error)
    {
        if (!Pop(stack, out byte[] publicKey, out error) || !Pop(stack, out byte[] signature, out error))
            return false;
        bool ok = checker.CheckSignature(signature, publicKey, scriptCode);
        if (!ok && signature.Length != 0)
        {
            error = ScriptError.SignatureFailed;
            return false;
        }

        PushBool(stack, ok);
        return !verify || PopBool(stack, out error);
    }

    private static bool CheckMultiSig(List<byte[]> stack, ReadOnlySpan<byte> scriptCode, ISignatureChecker checker, bool verify, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger keyCountValue, out error) || keyCountValue < 0 || keyCountValue > 128)
            return Fail(ScriptError.InvalidNumber, out error);
        int keyCount = (int)keyCountValue;
        var keys = new byte[keyCount][];
        for (int i = 0; i < keyCount; i++)
        {
            if (!Pop(stack, out keys[i], out error))
                return false;
        }

        if (!PopNum(stack, out BigInteger sigCountValue, out error) || sigCountValue < 0 || sigCountValue > keyCount)
            return Fail(ScriptError.InvalidNumber, out error);
        int sigCount = (int)sigCountValue;
        var sigs = new byte[sigCount][];
        for (int i = 0; i < sigCount; i++)
        {
            if (!Pop(stack, out sigs[i], out error))
                return false;
        }

        int keyIndex = 0;
        int sigIndex = 0;
        while (sigIndex < sigCount && keyIndex < keyCount)
        {
            if (checker.CheckSignature(sigs[sigIndex], keys[keyIndex], scriptCode))
                sigIndex++;
            keyIndex++;
        }

        bool ok = sigIndex == sigCount;
        if (!ok)
        {
            foreach (byte[] signature in sigs)
            {
                if (signature.Length != 0)
                {
                    error = ScriptError.SignatureFailed;
                    return false;
                }
            }
        }

        PushBool(stack, ok);
        return !verify || PopBool(stack, out error);
    }

    private static bool Split(List<byte[]> stack, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger at, out error) || !Pop(stack, out byte[] value, out error))
            return false;
        if (at < 0 || at > value.Length)
        {
            error = ScriptError.InvalidNumber;
            return false;
        }

        int position = (int)at;
        Push(stack, value[..position]);
        Push(stack, value[position..]);
        return true;
    }

    private static bool Num2Bin(List<byte[]> stack, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger size, out error) || !Pop(stack, out byte[] value, out error))
            return false;
        if (!ScriptNum.TryDecode(value, out BigInteger number, requireMinimal: false) || size > int.MaxValue || !ScriptNum.TryNum2Bin(number, (int)size, out byte[] encoded))
        {
            error = ScriptError.InvalidNumber;
            return false;
        }

        Push(stack, encoded);
        return true;
    }

    private static bool Divide(List<byte[]> stack, bool modulo, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger right, out error) || !PopNum(stack, out BigInteger left, out error))
            return false;
        if (right.IsZero)
        {
            error = ScriptError.DivisionByZero;
            return false;
        }

        BigInteger quotient = BigInteger.DivRem(left, right, out BigInteger remainder);
        Push(stack, ScriptNum.Encode(modulo ? remainder : quotient));
        return true;
    }

    private static bool Shift(List<byte[]> stack, bool left, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger bits, out error) || !PopNum(stack, out BigInteger value, out error) || bits < 0 || bits > 1_000_000)
        {
            error = error == ScriptError.None ? ScriptError.InvalidNumber : error;
            return false;
        }

        bool negative = value.Sign < 0;
        BigInteger magnitude = BigInteger.Abs(value);
        magnitude = left ? magnitude << (int)bits : magnitude >> (int)bits;
        if (negative && !magnitude.IsZero)
            magnitude = -magnitude;
        Push(stack, ScriptNum.Encode(magnitude));
        return true;
    }

    private static bool Within(List<byte[]> stack, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger max, out error) || !PopNum(stack, out BigInteger min, out error) || !PopNum(stack, out BigInteger value, out error))
            return false;
        PushBool(stack, value >= min && value < max);
        return true;
    }

    private static bool Unary(List<byte[]> stack, Func<BigInteger, BigInteger> operation, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger value, out error))
            return false;
        Push(stack, ScriptNum.Encode(operation(value)));
        return true;
    }

    private static bool BinaryNum(List<byte[]> stack, Func<BigInteger, BigInteger, BigInteger> operation, out ScriptError error)
    {
        if (!PopNum(stack, out BigInteger right, out error) || !PopNum(stack, out BigInteger left, out error))
            return false;
        Push(stack, ScriptNum.Encode(operation(left, right)));
        return true;
    }

    private static bool Hash(List<byte[]> stack, HashFn hash, out ScriptError error)
    {
        if (!Pop(stack, out byte[] value, out error))
            return false;
        Push(stack, hash(value));
        return true;
    }

    private delegate byte[] HashFn(ReadOnlySpan<byte> data);

    private static bool Binary(List<byte[]> stack, Func<byte[], byte[], byte[]> operation, out ScriptError error)
    {
        if (!Pop(stack, out byte[] right, out error) || !Pop(stack, out byte[] left, out error))
            return false;
        Push(stack, operation(left, right));
        return true;
    }

    private static bool Bitwise(List<byte[]> stack, Func<byte, byte, byte> operation, out ScriptError error)
    {
        if (!Pop(stack, out byte[] right, out error) || !Pop(stack, out byte[] left, out error))
            return false;
        if (left.Length != right.Length)
        {
            error = ScriptError.InvalidStackOperation;
            return false;
        }

        var result = new byte[left.Length];
        for (int i = 0; i < result.Length; i++)
            result[i] = operation(left[i], right[i]);
        Push(stack, result);
        return true;
    }

    private static bool MutateTop(List<byte[]> stack, Action<byte[]> mutate, out ScriptError error)
    {
        if (!Pop(stack, out byte[] value, out error))
            return false;
        mutate(value);
        Push(stack, value);
        return true;
    }

    private static bool PopNum(List<byte[]> stack, out BigInteger value, out ScriptError error)
    {
        value = BigInteger.Zero;
        if (!Pop(stack, out byte[] bytes, out error))
            return false;
        if (!ScriptNum.TryDecode(bytes, out value))
        {
            error = ScriptError.InvalidNumber;
            return false;
        }

        return true;
    }

    private static bool PopBool(List<byte[]> stack, out ScriptError error)
    {
        if (!Pop(stack, out byte[] value, out error))
            return false;
        if (!IsTrue(value))
        {
            error = ScriptError.VerifyFailed;
            return false;
        }

        return true;
    }

    private static bool Pop(List<byte[]> stack, out byte[] value, out ScriptError error)
    {
        value = [];
        if (stack.Count == 0)
        {
            error = ScriptError.InvalidStackOperation;
            return false;
        }

        value = stack[^1];
        stack.RemoveAt(stack.Count - 1);
        error = ScriptError.None;
        return true;
    }

    private static byte[] Pop(List<byte[]> stack)
    {
        byte[] value = stack[^1];
        stack.RemoveAt(stack.Count - 1);
        return value;
    }

    private static bool Peek(List<byte[]> stack, int depth, out byte[] value, out ScriptError error)
    {
        value = [];
        if ((uint)depth >= (uint)stack.Count)
        {
            error = ScriptError.InvalidStackOperation;
            return false;
        }

        value = stack[stack.Count - 1 - depth];
        error = ScriptError.None;
        return true;
    }

    private static bool Push(List<byte[]> stack, byte[] value)
    {
        stack.Add(value);
        return true;
    }

    private static bool PushCopy(List<byte[]> stack, byte[] value) => Push(stack, (byte[])value.Clone());

    private static bool PushBool(List<byte[]> stack, bool value) => Push(stack, value ? [0x01] : []);

    private static bool InsertCopy(List<byte[]> stack, int depth, byte[] value)
    {
        if ((uint)depth > (uint)stack.Count)
            return false;
        stack.Insert(stack.Count - depth, (byte[])value.Clone());
        return true;
    }

    private static bool Remove(List<byte[]> stack, int depth, out ScriptError error)
    {
        if ((uint)depth >= (uint)stack.Count)
        {
            error = ScriptError.InvalidStackOperation;
            return false;
        }

        stack.RemoveAt(stack.Count - 1 - depth);
        error = ScriptError.None;
        return true;
    }

    private static bool Move(List<byte[]> stack, int depth, out ScriptError error)
    {
        if (!Peek(stack, depth, out byte[] value, out error))
            return false;
        stack.RemoveAt(stack.Count - 1 - depth);
        Push(stack, value);
        return true;
    }

    private static bool Swap(List<byte[]> stack, int first, int second, out ScriptError error)
    {
        if (!Peek(stack, first, out byte[] a, out error) || !Peek(stack, second, out byte[] b, out error))
            return false;
        stack[stack.Count - 1 - first] = b;
        stack[stack.Count - 1 - second] = a;
        return true;
    }

    private static bool Rot(List<byte[]> stack, out ScriptError error) => Move(stack, 2, out error);

    private static bool Fail(ScriptError scriptError, out ScriptError error)
    {
        error = scriptError;
        return false;
    }

    private static bool True(ref ScriptError error)
    {
        error = ScriptError.None;
        return true;
    }

    private static bool Executing(Stack<bool> conditions)
    {
        foreach (bool condition in conditions)
        {
            if (!condition)
                return false;
        }

        return true;
    }

    private static bool IsTrue(byte[] value)
    {
        foreach (byte item in value)
        {
            if (item != 0)
                return true;
        }

        return false;
    }

    private static bool IsMinimalBoolean(byte[] value) => value.Length == 0 || value.AsSpan().SequenceEqual(new byte[] { 0x01 });

    private static bool IsPushOnly(ReadOnlySpan<byte> script)
    {
        int pc = 0;
        while (pc < script.Length)
        {
            if (!TryReadInstruction(script, ref pc, out int opcode, out _))
                return false;
            if (opcode > Op16)
                return false;
        }

        return true;
    }

    private static bool IsMinimalPush(int opcode, ReadOnlySpan<byte> data)
    {
        if (data.Length == 0)
            return opcode == Op0;
        if (data.Length == 1 && data[0] is >= 1 and <= 16)
            return false;
        if (data.Length == 1 && data[0] == 0x81)
            return false;
        if (data.Length <= 75)
            return opcode == data.Length;
        if (data.Length <= 255)
            return opcode == OpPushData1;
        if (data.Length <= ushort.MaxValue)
            return opcode == OpPushData2;
        return opcode == OpPushData4;
    }

    private static bool TryReadInstruction(ReadOnlySpan<byte> script, ref int pc, out int opcode, out ReadOnlySpan<byte> data)
    {
        opcode = 0;
        data = default;
        if ((uint)pc >= (uint)script.Length)
            return false;
        opcode = script[pc++];
        if (opcode is > 0 and < OpPushData1)
        {
            if (script.Length - pc < opcode)
                return false;
            data = script.Slice(pc, opcode);
            pc += opcode;
            return true;
        }

        if (opcode == OpPushData1)
            return ReadSized(script, ref pc, 1, out data);
        if (opcode == OpPushData2)
            return ReadSized(script, ref pc, 2, out data);
        if (opcode == OpPushData4)
            return ReadSized(script, ref pc, 4, out data);
        return true;
    }

    private static bool ReadSized(ReadOnlySpan<byte> script, ref int pc, int lengthBytes, out ReadOnlySpan<byte> data)
    {
        data = default;
        if (script.Length - pc < lengthBytes)
            return false;
        int length = lengthBytes switch
        {
            1 => script[pc],
            2 => script[pc] | (script[pc + 1] << 8),
            _ => (int)(script[pc] | (script[pc + 1] << 8) | (script[pc + 2] << 16) | (script[pc + 3] << 24)),
        };
        pc += lengthBytes;
        if (length < 0 || script.Length - pc < length)
            return false;
        data = script.Slice(pc, length);
        pc += length;
        return true;
    }

    private sealed class DisabledChecker : ISignatureChecker
    {
        public bool CheckSignature(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKey, ReadOnlySpan<byte> scriptCode) => false;

        public bool CheckLockTime(BigInteger lockTime) => false;

        public bool CheckSequence(BigInteger sequence) => false;
    }
}
