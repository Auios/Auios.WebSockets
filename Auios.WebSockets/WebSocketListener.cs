using System.Net;
using System.Net.Sockets;

namespace Auios.WebSockets
{
    public class WebSocketListener
    {
        public readonly TcpListener listener;
        public WebSocketListener(IPAddress address, int port) => listener = new(address, port);
        public void Start() => listener.Start();
        public void Stop() => listener.Stop();
        public bool Pending() => listener.Pending();
        public WebSocketClient AcceptWebSocketClient() => new WebSocketClient(listener.AcceptSocket());
    }
}