using System.Net;

namespace harp_csharp
{
    public abstract class HarpCallback
    {
        public abstract void Phase2(IPAddress address, VerifyPacket packet);
        public abstract void Run(IPAddress address);
    }
}