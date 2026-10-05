using Bsvlib.Core;
using Bsvlib.Spv;
using Xunit;

namespace Bsvlib.Spv.Tests;

public class HeaderChainTests
{
    private static readonly TxId Merkle = TxId.Parse("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    [Fact]
    public void Genesis_root_is_valid_and_a_broken_link_is_rejected()
    {
        var chain = new HeaderChain(Network.Mainnet);
        Assert.Equal(0, chain.Height);
        Assert.True(chain.IsValidRoot(0, chain.Tip.MerkleRoot));
        Assert.False(chain.IsValidRoot(1, chain.Tip.MerkleRoot));
        Assert.False(chain.TryAdd(new BlockHeader(1, chain.Tip.Hash, chain.Tip.MerkleRoot, chain.Tip.Time + 600, 0x1d00ffff, 1)));
        Assert.Equal(0, chain.Height);
        Assert.Equal(chain.Tip.Hash, Assert.Single(chain.Locators()));
    }

    [Fact]
    public void Regtest_extends_only_when_the_header_meets_the_current_target()
    {
        var chain = new HeaderChain(Network.Regtest);
        BlockHeader rejected = new(1, chain.Tip.Hash, Merkle, chain.Tip.Time + 600, 0x1d00ffff, 0);
        Assert.False(chain.TryAdd(rejected));

        BlockHeader next = Mine(chain);
        Assert.True(chain.TryAdd(next));
        Assert.Equal(1, chain.Height);
        Assert.True(chain.IsValidRoot(1, Merkle));
        Assert.False(chain.IsValidRoot(1, chain.GetHeader(0).MerkleRoot));
        Assert.Equal(next.Hash, chain.Locators()[0]);
        Assert.Equal(chain.GetHeader(0).Hash, chain.Locators()[^1]);
    }

    private static BlockHeader Mine(HeaderChain chain)
    {
        BlockHeader previous = chain.Tip;
        uint time = previous.Time + 600;
        uint bits = Difficulty.NextBits([previous], [ProofOfWork.Work(previous.Bits)], chain.Parameters, time);
        for (uint nonce = 0; nonce < 64; nonce++)
        {
            var header = new BlockHeader(1, previous.Hash, Merkle, time, bits, nonce);
            if (ProofOfWork.Check(header.Hash, bits, chain.Parameters.PowLimit))
                return header;
        }

        throw new InvalidOperationException("Regtest target rejected the first 64 nonces.");
    }
}
