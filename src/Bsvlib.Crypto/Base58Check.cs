namespace Bsvlib.Crypto;

/// <summary>Base58Check：payload 后附双重 SHA-256 的前 4 字节，再做 Base58。用于地址和 WIF。</summary>
public static class Base58Check
{
    private const string Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private const int ChecksumSize = 4;

    public static string Encode(ReadOnlySpan<byte> payload)
    {
        Span<byte> checksum = stackalloc byte[Hash256.Size];
        Hash256.Write(payload, checksum);

        var body = new byte[payload.Length + ChecksumSize];
        payload.CopyTo(body);
        checksum[..ChecksumSize].CopyTo(body.AsSpan(payload.Length));
        return EncodeRaw(body);
    }

    public static bool TryDecode(string text, out byte[] payload)
    {
        payload = [];
        if (string.IsNullOrEmpty(text) || !TryDecodeRaw(text, out var raw) || raw.Length < ChecksumSize)
            return false;

        int payloadLength = raw.Length - ChecksumSize;
        Span<byte> checksum = stackalloc byte[Hash256.Size];
        Hash256.Write(raw.AsSpan(0, payloadLength), checksum);
        if (!checksum[..ChecksumSize].SequenceEqual(raw.AsSpan(payloadLength)))
            return false;

        payload = raw[..payloadLength];
        return true;
    }

    private static string EncodeRaw(ReadOnlySpan<byte> data)
    {
        int zeros = 0;
        while (zeros < data.Length && data[zeros] == 0)
            zeros++;

        var digits = new byte[data.Length * 2];
        int length = 0;
        for (int i = zeros; i < data.Length; i++)
        {
            int carry = data[i];
            int j = 0;
            for (int k = digits.Length - 1; k >= digits.Length - length || carry != 0; k--, j++)
            {
                carry += 256 * digits[k];
                digits[k] = (byte)(carry % 58);
                carry /= 58;
            }

            length = j;
        }

        var chars = new char[zeros + length];
        for (int i = 0; i < zeros; i++)
            chars[i] = '1';
        for (int i = 0; i < length; i++)
            chars[zeros + i] = Alphabet[digits[digits.Length - length + i]];
        return new string(chars);
    }

    private static bool TryDecodeRaw(ReadOnlySpan<char> text, out byte[] data)
    {
        data = [];
        int zeros = 0;
        while (zeros < text.Length && text[zeros] == '1')
            zeros++;

        var bytes = new byte[text.Length];
        int length = 0;
        for (int i = zeros; i < text.Length; i++)
        {
            int value = Alphabet.IndexOf(text[i]);
            if (value < 0)
                return false;

            int carry = value;
            int j = 0;
            for (int k = bytes.Length - 1; k >= bytes.Length - length || carry != 0; k--, j++)
            {
                carry += 58 * bytes[k];
                bytes[k] = (byte)(carry % 256);
                carry /= 256;
            }

            length = j;
        }

        data = new byte[zeros + length];
        bytes.AsSpan(bytes.Length - length, length).CopyTo(data.AsSpan(zeros));
        return true;
    }
}
