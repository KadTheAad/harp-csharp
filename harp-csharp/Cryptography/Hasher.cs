using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace harp_csharp.Cryptography
{
    public class Hasher
    {
        private readonly SHA256 _sha;
        public Hasher()
        {
            _sha = SHA256.Create();
        }

        public byte[] Hash(byte[] bytes)
        {
            return _sha.ComputeHash(bytes);
        }

        public String HashBytes(string text)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(text);
            byte[] hash = Hash(bytes);
            StringBuilder builder = new StringBuilder();
            
            foreach (var b in hash)
            {
                StringBuilder str = new StringBuilder(8);
                int[] bl  = new int[8];

                for (int i = 0; i < bl.Length; i++)
                {               
                    bl[bl.Length - 1 - i] = ((b & (1 << i)) != 0) ? 1 : 0;
                }

                foreach ( int num in bl) str.Append(num);

                builder.Append(str);
            }

            return builder.ToString().Substring(2);
        }

        public static long Timestamp()
        {
            return (long)DateTime.UtcNow.Subtract(new DateTime(1970, 1, 1)).TotalSeconds;
        }
    }
}