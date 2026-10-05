using System.Text;

namespace Bsvlib.P2P;

/// <summary>
/// 本机节点对外公布的身份。协议版本、时间、地址和随机数由连接时填写，不在这里配置。
/// </summary>
public sealed class P2POptions
{
    public const int MaxUserAgentBytes = 4000;

    public P2POptions(string userAgent)
    {
        if (string.IsNullOrWhiteSpace(userAgent))
            throw new ArgumentException("User agent is required.", nameof(userAgent));
        if (Encoding.UTF8.GetByteCount(userAgent) > MaxUserAgentBytes)
            throw new ArgumentException($"User agent must be at most {MaxUserAgentBytes} bytes.", nameof(userAgent));
        UserAgent = userAgent;
    }

    /// <summary>写进 version 的用户代理，例如 /Bsvlib:0.1.0/。</summary>
    public string UserAgent { get; }

    /// <summary>本机目前看到的区块高度。每次拨号时读取。</summary>
    public int StartHeight { get; set; }

    /// <summary>本机提供的服务位。不对外提供区块时保持 0。</summary>
    public ulong Services { get; set; }

    /// <summary>是否接收交易通知。</summary>
    public bool Relay { get; set; } = true;
}
