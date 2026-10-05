using System.Security.Cryptography;
using System.Text;

namespace Bsvlib.Bips;

/// <summary>BIP-39 助记词。种子由规范化后的句子经 PBKDF2-HMAC-SHA512 导出。</summary>
public static class Mnemonic
{
    public static string Generate(int wordCount = 12, Wordlist? wordlist = null)
    {
        int entropyBytes = wordCount switch
        {
            12 => 16,
            15 => 20,
            18 => 24,
            21 => 28,
            24 => 32,
            _ => throw new ArgumentOutOfRangeException(nameof(wordCount), "Word count must be 12, 15, 18, 21, or 24."),
        };
        return FromEntropy(RandomNumberGenerator.GetBytes(entropyBytes), wordlist);
    }

    public static string FromEntropy(ReadOnlySpan<byte> entropy, Wordlist? wordlist = null)
    {
        if (!TryFromEntropy(entropy, out string? mnemonic, wordlist))
            throw new ArgumentException("Entropy must be 16, 20, 24, 28, or 32 bytes.", nameof(entropy));
        return mnemonic!;
    }

    public static bool TryFromEntropy(ReadOnlySpan<byte> entropy, out string? mnemonic, Wordlist? wordlist = null)
    {
        mnemonic = null;
        if (!IsValidEntropyLength(entropy.Length))
            return false;

        wordlist ??= Wordlist.English;
        int checksumBits = entropy.Length / 4;
        int wordCount = (entropy.Length * 8 + checksumBits) / 11;
        Span<byte> material = stackalloc byte[entropy.Length + 1];
        entropy.CopyTo(material);
        material[entropy.Length] = SHA256.HashData(entropy)[0];

        var words = new string[wordCount];
        for (int i = 0; i < wordCount; i++)
            words[i] = wordlist[ReadBits(material, i * 11, 11)];
        mnemonic = string.Join(' ', words);
        return true;
    }

    public static bool TryValidate(string mnemonic, out byte[]? entropy, Wordlist? wordlist = null)
    {
        entropy = null;
        if (!TryGetIndexes(mnemonic, wordlist ?? Wordlist.English, out int[]? indexes))
            return false;

        int wordCount = indexes!.Length;
        if (wordCount is not (12 or 15 or 18 or 21 or 24))
            return false;

        int entropyBits = wordCount * 11 * 32 / 33;
        int checksumBits = entropyBits / 32;
        var material = new byte[(entropyBits + checksumBits + 7) / 8];
        for (int i = 0; i < wordCount; i++)
            WriteBits(material, i * 11, 11, indexes[i]);

        entropy = material[..(entropyBits / 8)];
        byte expected = SHA256.HashData(entropy)[0];
        int shift = 8 - checksumBits;
        return (material[entropy.Length] >> shift) == (expected >> shift);
    }

    public static byte[] ToSeed(string mnemonic, string passphrase = "", Wordlist? wordlist = null)
    {
        if (!TryToSeed(mnemonic, out byte[]? seed, passphrase, wordlist))
            throw new FormatException("Mnemonic is not a valid BIP-39 sentence.");
        return seed!;
    }

    public static bool TryToSeed(string mnemonic, out byte[]? seed, string passphrase = "", Wordlist? wordlist = null)
    {
        seed = null;
        wordlist ??= Wordlist.English;
        if (!TryCanonicalize(mnemonic, wordlist, out string? sentence))
            return false;

        string password = sentence!.Normalize(NormalizationForm.FormKD);
        string salt = ("mnemonic" + passphrase).Normalize(NormalizationForm.FormKD);
        seed = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(password),
            Encoding.UTF8.GetBytes(salt),
            2048,
            HashAlgorithmName.SHA512,
            64);
        return true;
    }

    private static bool TryCanonicalize(string mnemonic, Wordlist wordlist, out string? sentence)
    {
        sentence = null;
        if (!TryGetIndexes(mnemonic, wordlist, out int[]? indexes))
            return false;
        if (!TryValidate(mnemonic, out _, wordlist))
            return false;

        var words = new string[indexes!.Length];
        for (int i = 0; i < words.Length; i++)
            words[i] = wordlist[indexes[i]];
        sentence = string.Join(' ', words);
        return true;
    }

    private static bool TryGetIndexes(string mnemonic, Wordlist wordlist, out int[]? indexes)
    {
        indexes = null;
        if (string.IsNullOrWhiteSpace(mnemonic))
            return false;

        string[] parts = mnemonic.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);
        var result = new int[parts.Length];
        for (int i = 0; i < parts.Length; i++)
        {
            if (!wordlist.TryGetIndex(parts[i], out result[i]))
                return false;
        }

        indexes = result;
        return true;
    }

    private static bool IsValidEntropyLength(int length) => length is 16 or 20 or 24 or 28 or 32;

    private static int ReadBits(ReadOnlySpan<byte> data, int offset, int count)
    {
        int value = 0;
        for (int i = 0; i < count; i++)
        {
            int position = offset + i;
            int bit = (data[position / 8] >> (7 - (position % 8))) & 1;
            value = (value << 1) | bit;
        }

        return value;
    }

    private static void WriteBits(Span<byte> data, int offset, int count, int value)
    {
        for (int i = count - 1; i >= 0; i--)
        {
            int position = offset + (count - 1 - i);
            if (((value >> i) & 1) == 0)
                continue;
            data[position / 8] |= (byte)(1 << (7 - (position % 8)));
        }
    }
}
