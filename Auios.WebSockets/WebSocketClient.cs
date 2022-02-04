using System;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Auios.WebSockets
{
    public class WebSocketClient
    {
        public readonly Socket socket;

        public WebSocketClient(Socket socket) => this.socket = socket;

        public void Close() => socket.Close();

        public EndPoint ip => socket.RemoteEndPoint;

        public int available => socket.Available;

        public byte[] Receive()
        {
            byte[] data = new byte[available];
            socket.Receive(data);
            return data;
        }

        public Frame ReceiveFrame()
        {
            byte[] data = Receive();
            Frame f;

            // Indicates that this is the final fragment in a message.  The first
            // fragment MAY also be the final fragment.
            f.fin = (data[0] & 0b1000_0000) != 0; // Is true if the message is finished sending.
            // MUST be 0 unless an extension is negotiated that defines meanings
            // for non-zero values.  If a nonzero value is received and none of
            // the negotiated extensions defines the meaning of such a nonzero
            // value, the receiving endpoint MUST _Fail the WebSocket
            // Connection_.
            f.rsv1 = (data[0] & 0b1000_0000) != 0;
            f.rsv2 = (data[0] & 0b0100_0000) != 0;
            f.rsv3 = (data[0] & 0b0010_0000) != 0;
            
            // Opcode:
            // 0 : denotes a continuation frame
            // 1 : denotes a text frame
            // 2 : denotes a binary frame
            // 3 - 7 : reserved for further non-control frames
            // 8 : denotes a connection close
            // 9 : denotes a ping
            // 10 : denotes a pong
            // 11 - 15 : reserved for further control frames
            f.op = data[0] & 0b0000_1111;
            // Defines whether the "Payload data" is masked.  If set to 1, a
            // masking key is present in masking-key, and this is used to unmask
            // the "Payload data" as per Section 5.3.  All frames sent from
            // client to server have this bit set to 1.
            f.mask = (data[1] & 0b1000_0000) != 0;
            
            // The length of the "Payload data", in bytes: if 0-125, that is the
            // payload length.  If 126, the following 2 bytes interpreted as a
            // 16-bit unsigned integer are the payload length.  If 127, the
            // following 8 bytes interpreted as a 64-bit unsigned integer (the
            // most significant bit MUST be 0) are the payload length.  Multibyte
            // length quantities are expressed in network byte order.  Note that
            // in all cases, the minimal number of bytes MUST be used to encode
            // the length, for example, the length of a 124-byte-long string
            // can't be encoded as the sequence 126, 0, 124.  The payload length
            // is the length of the "Extension data" + the length of the
            // "Application data".  The length of the "Extension data" may be
            // zero, in which case the payload length is the length of the
            // "Application data".
            f.len = data[1] & 0b0111_1111; // -128
            
            int offset = 2;
            
            if(f.len == 126)
            {
                f.len = BitConverter.ToUInt16(new[] {data[3], data[2]}, 0);
                offset = 4;
            }
            else if(f.len == 127)
            {
                //Console.WriteLine("msgLen == 127, needs uint64 to store msgLen");
                // msglen = BitConverter.ToUInt64(new byte[] { bytes[5], bytes[4], bytes[3], bytes[2], bytes[9], bytes[8], bytes[7], bytes[6] }, 0);
                // offset = 10;
            }

            f.data = Array.Empty<byte>();

            if(f.len == 0)
            {
                //Console.WriteLine("msgLen == 0");
            }
            else if(f.mask)
            {
                f.data = new byte[f.len];
                byte[] masks =
                {
                    data[offset],
                    data[offset + 1],
                    data[offset + 2],
                    data[offset + 3]
                };
                offset += 4;

                for(int i = 0; i < f.len; i++)
                {
                    f.data[i] = (byte)(data[offset + i] ^ masks[i % 4]);
                }
            }

            return f;
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

        public void Send(string message) => Send(Encoding.UTF8.GetBytes(message));
        public void SendRaw(string message) => socket.Send(Encoding.UTF8.GetBytes(message));

        public bool CompleteHandshake()
        {
            byte[] data = Receive();
            if(data.Length < 3) return false;
            
            string key = string.Empty;
            string request = Encoding.UTF8.GetString(data);
            string[] headers = request.Split(new[] {'\r', '\n'},
                StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);

            if(!request.Contains("GET") || !request.Contains("Sec-WebSocket-Key")) return false;
            
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
            string response = builder.ToString();
            
            SendRaw(response);
            
            return true;
        }
    }
}