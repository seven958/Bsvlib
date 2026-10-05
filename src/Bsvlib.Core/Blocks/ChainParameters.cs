using System.Numerics;

namespace Bsvlib.Core;

/// <summary>一条链的创世块和工作量参数，取值与 bitcoin-sv 的 chainparams 一致。</summary>
public sealed class ChainParameters
{
    private ChainParameters(
        BlockHeader genesis,
        BigInteger powLimit,
        int targetSpacing,
        int targetTimespan,
        int daaHeight,
        bool allowMinDifficultyBlocks,
        bool noRetargeting)
    {
        Genesis = genesis;
        PowLimit = powLimit;
        PowLimitCompact = ProofOfWork.EncodeCompact(powLimit);
        TargetSpacing = targetSpacing;
        TargetTimespan = targetTimespan;
        DaaHeight = daaHeight;
        AllowMinDifficultyBlocks = allowMinDifficultyBlocks;
        NoRetargeting = noRetargeting;
    }

    public BlockHeader Genesis { get; }

    public BigInteger PowLimit { get; }

    public uint PowLimitCompact { get; }

    public int TargetSpacing { get; }

    public int TargetTimespan { get; }

    public int DaaHeight { get; }

    public bool AllowMinDifficultyBlocks { get; }

    public bool NoRetargeting { get; }

    public int DifficultyAdjustmentInterval => TargetTimespan / TargetSpacing;

    public static ChainParameters For(Network network)
    {
        ArgumentNullException.ThrowIfNull(network);
        if (ReferenceEquals(network, Network.Mainnet))
            return Mainnet;
        if (ReferenceEquals(network, Network.Testnet))
            return Testnet;
        if (ReferenceEquals(network, Network.ScalingTestnet))
            return ScalingTestnet;
        if (ReferenceEquals(network, Network.Regtest))
            return Regtest;
        throw new ArgumentException($"Network {network.Name} has no chain parameters.", nameof(network));
    }

    private static readonly TxId GenesisMerkleRoot = TxId.Parse("4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b");

    private static readonly BigInteger CommonPowLimit = ProofOfWork.ParseUnsigned("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff");

    private static readonly ChainParameters Mainnet = new(
        new BlockHeader(1, default, GenesisMerkleRoot, 1_231_006_505, 0x1d00ffff, 2_083_236_893),
        CommonPowLimit,
        targetSpacing: 10 * 60,
        targetTimespan: 14 * 24 * 60 * 60,
        daaHeight: 504_031,
        allowMinDifficultyBlocks: false,
        noRetargeting: false);

    private static readonly ChainParameters Testnet = new(
        new BlockHeader(1, default, GenesisMerkleRoot, 1_296_688_602, 0x1d00ffff, 414_098_458),
        CommonPowLimit,
        targetSpacing: 10 * 60,
        targetTimespan: 14 * 24 * 60 * 60,
        daaHeight: 1_188_697,
        allowMinDifficultyBlocks: true,
        noRetargeting: false);

    private static readonly ChainParameters ScalingTestnet = new(
        new BlockHeader(1, default, GenesisMerkleRoot, 1_296_688_602, 0x1d00ffff, 414_098_458),
        CommonPowLimit,
        targetSpacing: 10 * 60,
        targetTimespan: 14 * 24 * 60 * 60,
        daaHeight: 2_200,
        allowMinDifficultyBlocks: false,
        noRetargeting: false);

    private static readonly ChainParameters Regtest = new(
        new BlockHeader(1, default, GenesisMerkleRoot, 1_296_688_602, 0x207fffff, 2),
        ProofOfWork.ParseUnsigned("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        targetSpacing: 10 * 60,
        targetTimespan: 14 * 24 * 60 * 60,
        daaHeight: 0,
        allowMinDifficultyBlocks: true,
        noRetargeting: true);
}
