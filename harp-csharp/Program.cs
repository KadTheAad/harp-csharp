using System;
using System.Net;
using System.Text;
using harp_csharp.Cryptography;
using harp_csharp.Cryptography.Encryption;

namespace harp_csharp
{
    internal class Program
    {
        class Callback : HarpCallback
        {
            public override void Phase2(IPAddress address, VerifyPacket packet)
            {
                Console.WriteLine("Phase 2: " + address);
            }

            public override void Run(IPAddress address)
            {
                Console.WriteLine("Run: " + address);
            }
        }

        public static void Main(string[] args)
        {
            Harp harp = new Harp(true, Encoding.UTF8.GetBytes("1"), Encoding.UTF8.GetBytes("2"), "1234",
                new Callback());
            Harp harp2 = new Harp(false, Encoding.UTF8.GetBytes("2"), Encoding.UTF8.GetBytes("1"), "1234",
                new Callback());
            harp.Run();
            harp2.Run();
        }
    }
}