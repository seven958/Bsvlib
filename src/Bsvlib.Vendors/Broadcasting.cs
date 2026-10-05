namespace Bsvlib.Vendors;

public enum BroadcastState
{
    Unknown,
    Pending,
    Seen,
    Mined,
    Rejected,
}

public sealed record BroadcastReceipt(Bsvlib.Core.TxId TxId, BroadcastState State, string Status, string? Detail);

public interface ITransactionBroadcaster
{
    Task<BroadcastReceipt> BroadcastAsync(Bsvlib.Core.Transaction transaction, CancellationToken cancellationToken = default);

    Task<BroadcastReceipt> GetStatusAsync(Bsvlib.Core.TxId txId, CancellationToken cancellationToken = default);
}
