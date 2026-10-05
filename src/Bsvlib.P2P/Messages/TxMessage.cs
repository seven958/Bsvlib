using Bsvlib.Core;

namespace Bsvlib.P2P;

public sealed class TxMessage : NetworkMessage
{
    public TxMessage(Transaction transaction) => Transaction = transaction ?? throw new ArgumentNullException(nameof(transaction));

    public override string Command => "tx";

    public Transaction Transaction { get; }

    public override int GetPayloadLength() => Transaction.GetSerializedLength();

    public override void WritePayload(Span<byte> destination) => Transaction.Write(destination);

    public static TxMessage? TryRead(ReadOnlySpan<byte> payload) =>
        Transaction.TryRead(payload, out Transaction? transaction, out int read) && read == payload.Length
            ? new TxMessage(transaction!)
            : null;
}
