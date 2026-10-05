using System.Numerics;
using Bsvlib.Core;
using Xunit;

namespace Bsvlib.Core.Tests;

public class ChainTests
{
    [Fact]
    public void Compact_difficulty_round_trips_the_network_limits()
    {
        Assert.Equal(0x1d00ffffu, ProofOfWork.EncodeCompact(ProofOfWork.DecodeCompact(0x1d00ffff, out _, out _)));
        Assert.Equal(0x207fffffu, ChainParameters.For(Network.Regtest).PowLimitCompact);
        Assert.Equal(0x1d00ffffu, ChainParameters.For(Network.Mainnet).PowLimitCompact);
    }

    [Theory]
    [InlineData("mainnet", "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f")]
    [InlineData("testnet", "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")]
    [InlineData("stn", "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943")]
    [InlineData("regtest", "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")]
    public void Genesis_header_matches_the_published_hash(string name, string hash)
    {
        ChainParameters parameters = ChainParameters.For(NetworkByName(name));
        Assert.Equal(hash, parameters.Genesis.Hash.ToString());
        Assert.True(ProofOfWork.Check(parameters.Genesis.Hash, parameters.Genesis.Bits, parameters.PowLimit));
    }

    [Fact]
    public void Two_week_retarget_eases_when_blocks_are_four_times_slower()
    {
        ChainParameters parameters = ChainParameters.For(Network.Mainnet);
        (BlockHeader[] headers, BigInteger[] work) = Period(parameters, 0x1c00ffff, parameters.TargetTimespan);
        Assert.Equal(0x1c00ffffu, Difficulty.NextBits(headers, work, parameters, 0));

        (headers, work) = Period(parameters, 0x1c00ffff, parameters.TargetTimespan * 4);
        Assert.Equal(0x1c03fffcu, Difficulty.NextBits(headers, work, parameters, 0));

        (headers, work) = Period(parameters, 0x1d00ffff, parameters.TargetTimespan * 4);
        Assert.Equal(parameters.PowLimitCompact, Difficulty.NextBits(headers, work, parameters, 0));
    }

    private static (BlockHeader[] Headers, BigInteger[] Work) Period(ChainParameters parameters, uint bits, long span)
    {
        var headers = new BlockHeader[parameters.DifficultyAdjustmentInterval];
        var work = new BigInteger[headers.Length];
        BigInteger blockWork = ProofOfWork.Work(bits);
        BigInteger sum = BigInteger.Zero;
        for (int i = 0; i < headers.Length; i++)
        {
            uint time = i == headers.Length - 1 ? (uint)span : 0;
            headers[i] = new BlockHeader(1, default, default, time, bits, 0);
            sum += blockWork;
            work[i] = sum;
        }

        return (headers, work);
    }

    private static Network NetworkByName(string name) => name switch
    {
        "mainnet" => Network.Mainnet,
        "testnet" => Network.Testnet,
        "stn" => Network.ScalingTestnet,
        "regtest" => Network.Regtest,
        _ => throw new ArgumentOutOfRangeException(nameof(name)),
    };
}
