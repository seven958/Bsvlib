namespace Bsvlib.P2P;

public interface IMessageHandler<T> where T : NetworkMessage
{
    ValueTask HandleAsync(Peer peer, T message, CancellationToken cancellationToken);
}

public sealed class MessageDispatcher
{
    private readonly Dictionary<Type, Func<Peer, NetworkMessage, CancellationToken, ValueTask>> _handlers = [];

    public void Register<T>(IMessageHandler<T> handler) where T : NetworkMessage
    {
        ArgumentNullException.ThrowIfNull(handler);
        _handlers[typeof(T)] = (peer, message, cancellationToken) => handler.HandleAsync(peer, (T)message, cancellationToken);
    }

    public ValueTask DispatchAsync(Peer peer, NetworkMessage message, CancellationToken cancellationToken)
    {
        if (_handlers.TryGetValue(message.GetType(), out Func<Peer, NetworkMessage, CancellationToken, ValueTask>? handler))
            return handler(peer, message, cancellationToken);
        return ValueTask.CompletedTask;
    }
}

public sealed class VersionHandler : IMessageHandler<VersionMessage>
{
    public async ValueTask HandleAsync(Peer peer, VersionMessage message, CancellationToken cancellationToken) =>
        await peer.SendAsync(VerAckMessage.Instance, cancellationToken).ConfigureAwait(false);
}

public sealed class PingHandler : IMessageHandler<PingMessage>
{
    public async ValueTask HandleAsync(Peer peer, PingMessage message, CancellationToken cancellationToken) =>
        await peer.SendAsync(new PongMessage(message.Nonce), cancellationToken).ConfigureAwait(false);
}
