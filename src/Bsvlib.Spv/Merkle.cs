using Bsvlib.Core;
using Bsvlib.Crypto;

namespace Bsvlib.Spv;

/// <summary>经典 Merkle 树。相邻相同哈希会被标成变异，对应 CVE-2012-2459。</summary>
public static class Merkle
{
    public static TxId ComputeRoot(IReadOnlyList<TxId> txIds) => ComputeRoot(txIds, out _);

    public static TxId ComputeRoot(IReadOnlyList<TxId> txIds, out bool mutated)
    {
        ArgumentNullException.ThrowIfNull(txIds);
        if (txIds.Count == 0)
            throw new ArgumentException("A Merkle tree needs at least one transaction.", nameof(txIds));

        var level = new List<TxId>(txIds);
        mutated = false;
        while (level.Count > 1)
        {
            for (int i = 0; i + 1 < level.Count; i += 2)
            {
                if (level[i].Equals(level[i + 1]))
                    mutated = true;
            }

            if ((level.Count & 1) == 1)
                level.Add(level[^1]);

            var next = new List<TxId>(level.Count / 2);
            for (int i = 0; i < level.Count; i += 2)
                next.Add(Parent(level[i], level[i + 1]));
            level = next;
        }

        return level[0];
    }

    public static IReadOnlyList<MerkleStep> CreateProof(IReadOnlyList<TxId> txIds, int index)
    {
        ArgumentNullException.ThrowIfNull(txIds);
        if ((uint)index >= (uint)txIds.Count)
            throw new ArgumentOutOfRangeException(nameof(index));

        var level = new List<TxId>(txIds);
        var steps = new List<MerkleStep>();
        int cursor = index;
        while (level.Count > 1)
        {
            bool odd = (level.Count & 1) == 1;
            if (odd && cursor == level.Count - 1)
                steps.Add(new MerkleStep(null, Duplicate: true));
            else
                steps.Add(new MerkleStep(level[cursor ^ 1], Duplicate: false));

            if (odd)
                level.Add(level[^1]);

            var next = new List<TxId>(level.Count / 2);
            for (int i = 0; i < level.Count; i += 2)
                next.Add(Parent(level[i], level[i + 1]));
            level = next;
            cursor >>= 1;
        }

        return steps;
    }

    public static bool TryComputeRoot(TxId txId, int index, IReadOnlyList<MerkleStep> proof, out TxId root)
    {
        root = txId;
        int cursor = index;
        foreach (MerkleStep step in proof)
        {
            if (step.Duplicate)
            {
                if ((cursor & 1) != 0)
                    return false;
                root = Parent(root, root);
            }
            else if (step.Sibling is not TxId sibling || sibling.Equals(root))
            {
                return false;
            }
            else
            {
                root = (cursor & 1) == 0 ? Parent(root, sibling) : Parent(sibling, root);
            }

            cursor >>= 1;
        }

        return true;
    }

    internal static TxId Parent(TxId left, TxId right)
    {
        Span<byte> pair = stackalloc byte[64];
        left.WriteWire(pair);
        right.WriteWire(pair[32..]);
        Span<byte> hash = stackalloc byte[32];
        Hash256.Write(pair, hash);
        return TxId.FromWire(hash);
    }
}

public readonly record struct MerkleStep(TxId? Sibling, bool Duplicate);
