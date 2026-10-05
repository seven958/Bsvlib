namespace Bsvlib.P2P;

internal static class StreamBytes
{
    public static async ValueTask ReadExactlyAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        int read = 0;
        while (read < buffer.Length)
        {
            int count = await stream.ReadAsync(buffer[read..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
                throw new EndOfStreamException();
            read += count;
        }
    }

    public static async ValueTask<ulong> ReadVarIntAsync(Stream stream, CancellationToken cancellationToken)
    {
        var first = new byte[1];
        await ReadExactlyAsync(stream, first, cancellationToken).ConfigureAwait(false);
        if (first[0] < 0xFD)
            return first[0];

        int size = first[0] switch
        {
            0xFD => 2,
            0xFE => 4,
            _ => 8,
        };
        var rest = new byte[size];
        await ReadExactlyAsync(stream, rest, cancellationToken).ConfigureAwait(false);
        var encoded = new byte[1 + size];
        encoded[0] = first[0];
        rest.CopyTo(encoded, 1);
        if (!Bsvlib.Core.VarInt.TryRead(encoded, out ulong value, out _))
            throw new InvalidDataException("Invalid variable integer.");
        return value;
    }
}
