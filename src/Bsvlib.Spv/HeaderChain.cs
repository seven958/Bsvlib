using System.Numerics;
using Bsvlib.Core;

namespace Bsvlib.Spv;

/// <summary>
/// 从创世块连起来的区块头。每一块都要接上前一块，并且难度和工作量证明都成立。
/// </summary>
public sealed class HeaderChain : IChainTracker
{
    private readonly List<BlockHeader> _headers = [];
    private readonly List<BigInteger> _work = [];
    private readonly Dictionary<TxId, int> _heights = [];

    public HeaderChain(Network network)
    {
        Parameters = ChainParameters.For(network);
        Add(Parameters.Genesis, ProofOfWork.Work(Parameters.Genesis.Bits));
    }

    public ChainParameters Parameters { get; }

    public int Height => _headers.Count - 1;

    public BlockHeader Tip => _headers[^1];

    public BlockHeader GetHeader(int height)
    {
        if ((uint)height >= (uint)_headers.Count)
            throw new ArgumentOutOfRangeException(nameof(height));
        return _headers[height];
    }

    public bool TryGetHeight(TxId hash, out int height) => _heights.TryGetValue(hash, out height);

    public IReadOnlyList<TxId> Locators()
    {
        var locators = new List<TxId>(32);
        int height = Height;
        int step = 1;
        while (true)
        {
            locators.Add(_headers[height].Hash);
            if (height == 0 || locators.Count == 2000)
                break;
            int next = Math.Max(height - step, 0);
            if (locators.Count > 10)
                step *= 2;
            height = next;
        }

        return locators;
    }

    public bool TryAdd(BlockHeader header)
    {
        ArgumentNullException.ThrowIfNull(header);
        if (_heights.ContainsKey(header.Hash))
            return true;
        if (!header.PreviousBlock.Equals(Tip.Hash))
            return false;
        if (header.Bits != Difficulty.NextBits(_headers, _work, Parameters, header.Time))
            return false;
        if (!ProofOfWork.Check(header.Hash, header.Bits, Parameters.PowLimit))
            return false;
        Add(header, _work[^1] + ProofOfWork.Work(header.Bits));
        return true;
    }

    public bool IsValidRoot(long blockHeight, TxId merkleRoot)
    {
        if (blockHeight < 0 || blockHeight > Height)
            return false;
        return _headers[(int)blockHeight].MerkleRoot.Equals(merkleRoot);
    }

    private void Add(BlockHeader header, BigInteger work)
    {
        _heights.Add(header.Hash, _headers.Count);
        _headers.Add(header);
        _work.Add(work);
    }
}
