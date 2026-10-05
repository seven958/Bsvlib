using Bsvlib.Bips;
using Bsvlib.Core;
using Xunit;

namespace Bsvlib.Bips.Tests;

public class MnemonicTests
{
    private const string Abandon =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    [Fact]
    public void English_wordlist_has_the_bip39_boundaries()
    {
        Assert.Equal(2048, Wordlist.English.Count);
        Assert.Equal("abandon", Wordlist.English[0]);
        Assert.Equal("zoo", Wordlist.English[2047]);
    }

    [Fact]
    public void All_zero_entropy_matches_the_published_mnemonic_and_seeds()
    {
        string mnemonic = Mnemonic.FromEntropy(new byte[16]);
        Assert.Equal(Abandon, mnemonic);
        Assert.True(Mnemonic.TryValidate(mnemonic, out byte[]? entropy));
        Assert.Equal(new byte[16], entropy);

        Assert.Equal(
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4",
            Convert.ToHexString(Mnemonic.ToSeed(mnemonic)).ToLowerInvariant());
        Assert.Equal(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
            Convert.ToHexString(Mnemonic.ToSeed(Abandon.ToUpperInvariant(), "TREZOR")).ToLowerInvariant());
    }

    [Fact]
    public void A_broken_checksum_is_rejected_and_a_generated_sentence_validates()
    {
        Assert.False(Mnemonic.TryValidate(Abandon.Replace("about", "abandon"), out _));
        string generated = Mnemonic.Generate(24);
        Assert.Equal(24, generated.Split(' ').Length);
        Assert.True(Mnemonic.TryValidate(generated, out _));
    }
}

public class HdKeyTests
{
    private static readonly byte[] Seed = Convert.FromHexString("000102030405060708090a0b0c0d0e0f");

    [Theory]
    [InlineData("m",
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
        "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8")]
    [InlineData("m/0'",
        "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
        "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw")]
    [InlineData("m/0'/1",
        "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
        "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ")]
    [InlineData("m/0'/1/2'",
        "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
        "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5")]
    [InlineData("m/0'/1/2'/2",
        "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
        "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV")]
    [InlineData("m/0'/1/2'/2/1000000000",
        "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
        "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy")]
    public void Bip32_vector_1_matches_the_published_extended_keys(string path, string expectedPrivate, string expectedPublic)
    {
        HdPrivateKey key = HdPrivateKey.FromSeed(Seed, Network.Mainnet).DerivePath(path);
        Assert.Equal(expectedPrivate, key.ToExtendedKey());
        Assert.Equal(expectedPublic, key.PublicKey.ToExtendedKey());
        Assert.True(HdPrivateKey.TryParse(expectedPrivate, Network.Mainnet, out HdPrivateKey? parsed));
        Assert.Equal(expectedPrivate, parsed!.ToExtendedKey());
    }

    [Fact]
    public void Public_derivation_matches_the_private_child_and_rejects_hardened_indexes()
    {
        HdPrivateKey parent = HdPrivateKey.FromSeed(Seed, Network.Mainnet).DerivePath("m/0'");
        Assert.Equal(parent.Derive(1).PublicKey.ToExtendedKey(), parent.PublicKey.Derive(1).ToExtendedKey());
        Assert.False(parent.PublicKey.TryDerive(0x8000_0000, out _));
    }

    [Fact]
    public void Testnet_master_key_uses_the_tprv_version()
    {
        HdPrivateKey main = HdPrivateKey.FromSeed(Seed, Network.Mainnet);
        HdPrivateKey test = HdPrivateKey.FromSeed(Seed, Network.Testnet);
        Assert.StartsWith("tprv", test.ToExtendedKey());
        Assert.Equal(main.Key.ToBytes(), test.Key.ToBytes());
        Assert.False(HdPrivateKey.TryParse(main.ToExtendedKey(), Network.Testnet, out _));
    }

    [Theory]
    [InlineData("xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL")]
    [InlineData("xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx")]
    [InlineData("xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ")]
    public void Invalid_extended_keys_are_rejected(string text)
    {
        Assert.False(HdPrivateKey.TryParse(text, Network.Mainnet, out _));
        Assert.False(HdPublicKey.TryParse(text, Network.Mainnet, out _));
    }

    [Fact]
    public void Bsv_bip44_path_derives_a_key_that_matches_its_public_child()
    {
        Assert.Equal("m/44'/236'/0'/0/0", Bip44.Path());
        HdPrivateKey account = HdPrivateKey.FromSeed(Seed, Network.Mainnet).DerivePath(Bip44.Path());
        Assert.Equal(account.PublicKey.Key, account.Key.GetPublicKey());
        Assert.False(account.TryDerivePath("44'/236'/0'/0/0", out _));
    }
}
