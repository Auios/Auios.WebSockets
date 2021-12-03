using System;
using System.Net.Sockets;
using System.Text;

namespace Auios.WebSockets
{
    public class WebSocketClient
    {
        public readonly Socket socket;

        public WebSocketClient(Socket socket)
        {
            this.socket = socket;
        }

        public void Close() => socket.Close();

        public string ip => socket.RemoteEndPoint.ToString();

        public int available => socket.Available;

        public byte[] ReceiveRaw()
        {
            byte[] data = new byte[available];
            socket.Receive(data);
            return data;
        }

        public byte[] Receive()
        {
            byte[] data = ReceiveRaw();

            bool finished = (data[0] & 0b1000_0000) != 0; // Is true if the message is finished sending.
            bool mask = (data[1] & 0b1000_0000) != 0; // Must be true. All messages have this bit set.
            int opCode = data[0] & 0b0000_1111; // 1 = Text message.
            int msgLen = data[1] & 0b0111_1111; // -128
            int offset = 2;
            
            if(msgLen == 126)
            {
                msgLen = BitConverter.ToUInt16(new byte[] {data[3], data[2]}, 0);
                offset = 4;
            }
            else if(msgLen == 127)
            {
                //Console.WriteLine("msgLen == 127, needs uint64 to store msgLen");
                // msglen = BitConverter.ToUInt64(new byte[] { bytes[5], bytes[4], bytes[3], bytes[2], bytes[9], bytes[8], bytes[7], bytes[6] }, 0);
                // offset = 10;
            }

            byte[] decoded = Array.Empty<byte>();

            if(msgLen == 0)
            {
                //Console.WriteLine("msgLen == 0");
            }
            else if(mask)
            {
                decoded = new byte[msgLen];
                byte[] masks =
                {
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3]
                };
                offset += 4;

                for(int i = 0; i < msgLen; i++)
                {
                    decoded[i] = (byte)(data[offset + i] ^ masks[i % 4]);
                }
            }

            return decoded;
        }

        public void Send(byte[] data)
        {
            int indexStart;
            byte[] message;
            if(data.Length <= 125)
            {
                indexStart = 2;
                message = new byte[data.Length + 2];
                message[1] = (byte)data.Length;
            }
            else if(data.Length is >= 126 and <= 65535)
            {
                indexStart = 4;
                message = new byte[data.Length + 4];
                message[1] = 126;
                message[2] = (byte)((data.Length >> 8) & 255);
                message[3] = (byte)((data.Length >> 0) & 255);
            }
            else
            {
                ulong msgLen = (ulong)data.Length; 
                message = new byte[data.Length + 10];
                indexStart = 10;
                message[1] = 127;
                message[2] = (byte)((msgLen >> 56) & 255);
                message[3] = (byte)((msgLen >> 48) & 255);
                message[4] = (byte)((msgLen >> 40) & 255);
                message[5] = (byte)((msgLen >> 32) & 255);
                message[6] = (byte)((msgLen >> 24) & 255);
                message[7] = (byte)((msgLen >> 16) & 255);
                message[8] = (byte)((msgLen >> 8) & 255);
                message[9] = (byte)((msgLen >> 0) & 255);
            }
            
            message[0] = 0b1000_0001; //129

            Array.Copy(data, 0, message, indexStart, data.Length);
            
            socket.Send(message);
        }

        public void Send(string message)
        {
            Send(Encoding.UTF8.GetBytes(message));
        }

        public bool CompleteHandshake()
        {
            byte[] data = ReceiveRaw();
            if(data.Length < 3) return false;
            
            string key = string.Empty;
            string header = Encoding.UTF8.GetString(data);
            string[] headers = header.Split(new[] {'\r', '\n'},
                StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

            if(!header.Contains("GET") || !header.Contains("Sec-WebSocket-Key")) return false;
            
            foreach(string line in headers)
            {
                string[] pair = line.Split(':',
                    StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
                if(pair.Length == 2)
                {
                    if(pair[0] == "Sec-WebSocket-Key")
                    {
                        key = pair[1];
                        break;
                    }
                }
            }

            if(key == String.Empty) return false;

            const string eol = "\r\n";
            byte[] keyRaw = Encoding.UTF8.GetBytes($"{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            byte[] keyHash = System.Security.Cryptography.SHA1.Create().ComputeHash(keyRaw);
            string key64 = Convert.ToBase64String(keyHash);

            StringBuilder builder = new StringBuilder();
            builder.Append($"HTTP/1.1 101 Switching Protocols{eol}");
            builder.Append($"Connection: Upgrade{eol}");
            builder.Append($"Upgrade: websocket{eol}");
            builder.Append($"Sec-WebSocket-Accept: {key64}{eol}");
            builder.Append(eol);
            Send(builder.ToString());
            
            return true;
        }
    }
}