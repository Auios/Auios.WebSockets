namespace Auios.WebSockets
{
    public struct Frame
    {
        public bool fin;
        public bool rsv1;
        public bool rsv2;
        public bool rsv3;
        public int op;
        public bool mask;
        public int len;
        public byte[] data;
    }
}