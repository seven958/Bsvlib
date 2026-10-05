using System.Buffers.Binary;

namespace Bsvlib.Core;

/// <summary>脚本字节。这里只构造和识别 P2PKH / P2SH，不执行脚本。</summary>
public sealed class Script : IEquatable<Script>
{
    private const byte OpDup = 0x76;
    private const byte OpHash160 = 0xA9;
    private const byte OpEqual = 0x87;
    private const byte OpEqualVerify = 0x88;
    private const byte OpCheckSig = 0xAC;
    private const byte OpCodeSeparator = 0xAB;
    private const byte OpPushData1 = 0x4C;
    private const byte OpPushData2 = 0x4D;
    private const byte OpPushData4 = 0x4E;

    private readonly byte[] _bytes;

    public Script(ReadOnlySpan<byte> bytes) => _bytes = bytes.ToArray();

    public static Script Empty { get; } = new([]);

    public ReadOnlyMemory<byte> Bytes => _bytes;

    public static Script P2pkhLock(ReadOnlySpan<byte> hash160)
    {
        if (hash160.Length != 20)
            throw new ArgumentException("P2PKH hash must be 20 bytes.", nameof(hash160));

        var script = new byte[25];
        script[0] = OpDup;
        script[1] = OpHash160;
        script[2] = 0x14;
        hash160.CopyTo(script.AsSpan(3));
        script[23] = OpEqualVerify;
        script[24] = OpCheckSig;
        return new Script(script);
    }

    public static Script P2shLock(ReadOnlySpan<byte> hash160)
    {
        if (hash160.Length != 20)
            throw new ArgumentException("P2SH hash must be 20 bytes.", nameof(hash160));

        var script = new byte[23];
        script[0] = OpHash160;
        script[1] = 0x14;
        hash160.CopyTo(script.AsSpan(2));
        script[22] = OpEqual;
        return new Script(script);
    }

    public static Script P2pkhUnlock(ReadOnlySpan<byte> signatureWithType, ReadOnlySpan<byte> publicKey)
    {
        var builder = new ScriptBuilder(signatureWithType.Length + publicKey.Length + 4);
        builder.AddData(signatureWithType);
        builder.AddData(publicKey);
        return builder.Build();
    }

    public bool TryGetP2pkhHash(Span<byte> hash160)
    {
        if (hash160.Length < 20 || _bytes.Length != 25)
            return false;
        if (_bytes[0] != OpDup || _bytes[1] != OpHash160 || _bytes[2] != 0x14 || _bytes[23] != OpEqualVerify || _bytes[24] != OpCheckSig)
            return false;
        _bytes.AsSpan(3, 20).CopyTo(hash160);
        return true;
    }

    /// <summary>Sighash 使用的 scriptCode 会去掉 OP_CODESEPARATOR。格式损坏时保留原脚本。</summary>
    public Script WithoutCodeSeparators()
    {
        if (_bytes.AsSpan().IndexOf(OpCodeSeparator) < 0)
            return this;

        var output = new byte[_bytes.Length];
        int written = 0;
        int offset = 0;
        while (offset < _bytes.Length)
        {
            if (!TryGetInstructionLength(_bytes, offset, out int length))
                return this;
            if (_bytes[offset] != OpCodeSeparator)
            {
                _bytes.AsSpan(offset, length).CopyTo(output.AsSpan(written));
                written += length;
            }

            offset += length;
        }

        return new Script(output.AsSpan(0, written));
    }

    public bool Equals(Script? other) => other is not null && _bytes.AsSpan().SequenceEqual(other._bytes);

    public override bool Equals(object? obj) => obj is Script other && Equals(other);

    public override int GetHashCode()
    {
        var hash = new HashCode();
        hash.AddBytes(_bytes);
        return hash.ToHashCode();
    }

    private static bool TryGetInstructionLength(ReadOnlySpan<byte> script, int offset, out int length)
    {
        length = 0;
        if ((uint)offset >= (uint)script.Length)
            return false;

        byte op = script[offset];
        if (op is > 0 and < OpPushData1)
        {
            if (script.Length - offset - 1 < op)
                return false;
            length = 1 + op;
            return true;
        }

        if (op == OpPushData1)
        {
            if (script.Length - offset < 2)
                return false;
            int count = script[offset + 1];
            if (script.Length - offset - 2 < count)
                return false;
            length = 2 + count;
            return true;
        }

        if (op == OpPushData2)
        {
            if (script.Length - offset < 3)
                return false;
            int count = BinaryPrimitives.ReadUInt16LittleEndian(script[(offset + 1)..]);
            if (script.Length - offset - 3 < count)
                return false;
            length = 3 + count;
            return true;
        }

        if (op == OpPushData4)
        {
            if (script.Length - offset < 5)
                return false;
            uint count = BinaryPrimitives.ReadUInt32LittleEndian(script[(offset + 1)..]);
            if (count > int.MaxValue || script.Length - offset - 5 < count)
                return false;
            length = 5 + (int)count;
            return true;
        }

        length = 1;
        return true;
    }

    private sealed class ScriptBuilder
    {
        private byte[] _buffer;
        private int _length;

        public ScriptBuilder(int capacity) => _buffer = new byte[Math.Max(capacity, 16)];

        public void AddData(ReadOnlySpan<byte> data)
        {
            if (data.Length == 0)
            {
                AddByte(0);
                return;
            }

            if (data.Length <= 75)
            {
                AddByte((byte)data.Length);
            }
            else if (data.Length <= byte.MaxValue)
            {
                AddByte(OpPushData1);
                AddByte((byte)data.Length);
            }
            else if (data.Length <= ushort.MaxValue)
            {
                AddByte(OpPushData2);
                Span<byte> len = stackalloc byte[2];
                BinaryPrimitives.WriteUInt16LittleEndian(len, (ushort)data.Length);
                Add(len);
            }
            else
            {
                AddByte(OpPushData4);
                Span<byte> len = stackalloc byte[4];
                BinaryPrimitives.WriteUInt32LittleEndian(len, (uint)data.Length);
                Add(len);
            }

            Add(data);
        }

        public Script Build() => new(_buffer.AsSpan(0, _length));

        private void AddByte(byte value)
        {
            Ensure(1);
            _buffer[_length++] = value;
        }

        private void Add(ReadOnlySpan<byte> data)
        {
            Ensure(data.Length);
            data.CopyTo(_buffer.AsSpan(_length));
            _length += data.Length;
        }

        private void Ensure(int extra)
        {
            if (_length + extra <= _buffer.Length)
                return;
            int size = Math.Max(_buffer.Length * 2, _length + extra);
            Array.Resize(ref _buffer, size);
        }
    }
}
