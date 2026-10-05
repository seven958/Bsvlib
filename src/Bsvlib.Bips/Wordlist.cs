namespace Bsvlib.Bips;

/// <summary>BIP-39 词表。内置英文表，其它语言用 <see cref="Create"/> 传入 2048 个词。</summary>
public sealed class Wordlist
{
    public const int Length = 2048;

    private readonly string[] _words;
    private readonly Dictionary<string, int> _indexes;

    private Wordlist(string[] words)
    {
        _words = words;
        _indexes = new Dictionary<string, int>(words.Length, StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < words.Length; i++)
            _indexes.Add(words[i], i);
    }

    public static Wordlist English { get; } = LoadEnglish();

    public int Count => _words.Length;

    public string this[int index] => _words[index];

    public static Wordlist Create(IReadOnlyList<string> words)
    {
        ArgumentNullException.ThrowIfNull(words);
        if (words.Count != Length)
            throw new ArgumentException($"A BIP-39 wordlist contains {Length} words.", nameof(words));

        var copy = new string[Length];
        var seen = new HashSet<string>(Length, StringComparer.OrdinalIgnoreCase);
        for (int i = 0; i < Length; i++)
        {
            string word = words[i] ?? throw new ArgumentException("Wordlist contains a null word.", nameof(words));
            if (word.Length == 0 || word.Any(char.IsWhiteSpace) || !seen.Add(word))
                throw new ArgumentException($"Wordlist entry {i} is empty, contains whitespace, or is duplicated.", nameof(words));
            copy[i] = word;
        }

        return new Wordlist(copy);
    }

    public bool TryGetIndex(string word, out int index) => _indexes.TryGetValue(word, out index);

    private static Wordlist LoadEnglish()
    {
        var assembly = typeof(Wordlist).Assembly;
        using Stream stream = assembly.GetManifestResourceStream("Bsvlib.Bips.Wordlists.english.txt")
            ?? throw new InvalidOperationException("The English BIP-39 wordlist is not embedded.");
        using var reader = new StreamReader(stream);
        var words = new List<string>(Length);
        while (reader.ReadLine() is string line)
        {
            if (line.Length > 0)
                words.Add(line);
        }

        return Create(words);
    }
}
