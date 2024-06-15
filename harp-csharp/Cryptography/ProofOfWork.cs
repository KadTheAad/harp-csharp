using System;
using System.Linq;
using System.Text;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace harp_csharp.Cryptography
{
    public static class ProofOfWork
    {
        private const bool Verbose = false;
        private const string Difficulty = "00000";
        private const long Version = 2;
        private const long Bits = 419520339;

        public static bool Verify(byte[] starter, byte[] signature, long timestamp, long nonce)
        {
            return Verify(GetMessage(starter, signature, timestamp), nonce);
        }

        private static bool Verify(string message, long nonce)
        {
            using SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(sha256.ComputeHash(Encoding.UTF8.GetBytes(message + nonce)));
            string hashTest = BitConverter.ToString(hash.Reverse().ToArray()).Replace("-", "");

            if (Verbose) Console.WriteLine(hashTest);

            return hashTest.StartsWith(Difficulty, StringComparison.Ordinal);
        }

        public static long Get(byte[] starter, byte[] signature, long timestamp)
        {
            string message = GetMessage(starter, signature, timestamp);
            long nonce = 0;
            bool found = false;

            Parallel.For(0L, long.MaxValue, (i, state) =>
            {
                if (!Verify(message, i)) return;
                nonce = i;
                found = true;
                state.Stop();
            });

            if (found) return nonce;
            throw new InvalidOperationException("Failed to find a valid nonce");
        }
        

        public static string GetMessage(byte[] starter, byte[] signature, long timestamp)
        {
            return Version + Encoding.UTF8.GetString(starter.Reverse().ToArray()) + Encoding.UTF8.GetString(signature.Reverse().ToArray()) + timestamp + Bits;
        }
    }
}