namespace Bsvlib.Crypto;

/// <summary>
/// RIPEMD-160。系统加密库不提供该算法，地址的 HASH160 需要它。
/// 实现依据 Dobbertin、Bosselaers、Preneel 的原始规范。
/// </summary>
public static class Ripemd160
{
    public const int Size = 20;

    private static readonly int[] LeftIndex =
    [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
    ];

    private static readonly int[] RightIndex =
    [
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
    ];

    private static readonly int[] LeftShift =
    [
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
    ];

    private static readonly int[] RightShift =
    [
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
    ];

    private static readonly uint[] LeftConstant = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];
    private static readonly uint[] RightConstant = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

    public static byte[] Compute(ReadOnlySpan<byte> data)
    {
        var hash = new byte[Size];
        Write(data, hash);
        return hash;
    }

    public static void Write(ReadOnlySpan<byte> data, Span<byte> destination)
    {
        if (destination.Length < Size)
            throw new ArgumentException($"Destination must be at least {Size} bytes.", nameof(destination));

        uint h0 = 0x67452301;
        uint h1 = 0xEFCDAB89;
        uint h2 = 0x98BADCFE;
        uint h3 = 0x10325476;
        uint h4 = 0xC3D2E1F0;

        Span<byte> block = stackalloc byte[64];
        int offset = 0;
        while (data.Length - offset >= 64)
        {
            Compress(data.Slice(offset, 64), ref h0, ref h1, ref h2, ref h3, ref h4);
            offset += 64;
        }

        int tail = data.Length - offset;
        block.Clear();
        data.Slice(offset).CopyTo(block);
        block[tail] = 0x80;
        ulong bitLength = (ulong)data.Length << 3;
        if (tail >= 56)
        {
            Compress(block, ref h0, ref h1, ref h2, ref h3, ref h4);
            block.Clear();
        }

        System.Buffers.Binary.BinaryPrimitives.WriteUInt64LittleEndian(block.Slice(56), bitLength);
        Compress(block, ref h0, ref h1, ref h2, ref h3, ref h4);

        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination, h0);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination[4..], h1);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination[8..], h2);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination[12..], h3);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32LittleEndian(destination[16..], h4);
    }

    private static void Compress(ReadOnlySpan<byte> block, ref uint h0, ref uint h1, ref uint h2, ref uint h3, ref uint h4)
    {
        Span<uint> words = stackalloc uint[16];
        for (int i = 0; i < 16; i++)
            words[i] = System.Buffers.Binary.BinaryPrimitives.ReadUInt32LittleEndian(block[(i * 4)..]);

        uint a = h0, b = h1, c = h2, d = h3, e = h4;
        uint aa = h0, bb = h1, cc = h2, dd = h3, ee = h4;

        for (int j = 0; j < 80; j++)
        {
            int round = j >> 4;
            uint left = RotateLeft(a + Choose(j, b, c, d) + words[LeftIndex[j]] + LeftConstant[round], LeftShift[j]) + e;
            a = e;
            e = d;
            d = RotateLeft(c, 10);
            c = b;
            b = left;

            uint right = RotateLeft(aa + Choose(79 - j, bb, cc, dd) + words[RightIndex[j]] + RightConstant[round], RightShift[j]) + ee;
            aa = ee;
            ee = dd;
            dd = RotateLeft(cc, 10);
            cc = bb;
            bb = right;
        }

        uint chain = h1 + c + dd;
        h1 = h2 + d + ee;
        h2 = h3 + e + aa;
        h3 = h4 + a + bb;
        h4 = h0 + b + cc;
        h0 = chain;
    }

    private static uint Choose(int j, uint x, uint y, uint z) => j switch
    {
        < 16 => x ^ y ^ z,
        < 32 => (x & y) | (~x & z),
        < 48 => (x | ~y) ^ z,
        < 64 => (x & z) | (y & ~z),
        _ => x ^ (y | ~z),
    };

    private static uint RotateLeft(uint value, int bits) => (value << bits) | (value >> (32 - bits));
}
