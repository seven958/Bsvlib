namespace Bsvlib.Bips;

/// <summary>BIP-44 账户路径。BSV 的币种编号是 236。</summary>
public static class Bip44
{
    public const uint Purpose = 44;

    public const uint BsvCoinType = 236;

    public static string Path(uint account = 0, uint change = 0, uint index = 0) =>
        FormattableString.Invariant($"m/{Purpose}'/{BsvCoinType}'/{account}'/{change}/{index}");
}
