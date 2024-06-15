using System;
using System.Security.Cryptography;
using System.Text;

namespace harp_csharp.Cryptography.Encryption
{
    public static class SymmetricEncryption
    {
        public static byte[] Encrypt(byte[] data, string password)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = GenerateKeyFromPassword(password);
            aesAlg.GenerateIV();

            ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

            using var msEncrypt = new System.IO.MemoryStream();
            // Write IV to the beginning of the stream
            msEncrypt.Write(aesAlg.IV, 0, aesAlg.IV.Length);

            using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
            {
                csEncrypt.Write(data, 0, data.Length);
                csEncrypt.FlushFinalBlock();
            }
            return msEncrypt.ToArray();
        }

        public static byte[] Decrypt(byte[] encryptedData, string password)
        {
            using Aes aesAlg = Aes.Create();
            aesAlg.Key = GenerateKeyFromPassword(password);
        
            // Extract IV from the beginning of the encrypted data
            byte[] iv = new byte[aesAlg.BlockSize / 8]; // IV size in bytes
            Array.Copy(encryptedData, 0, iv, 0, iv.Length);
            aesAlg.IV = iv;

            ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

            using var msDecrypt = new System.IO.MemoryStream(encryptedData, iv.Length, encryptedData.Length - iv.Length);
            using var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
            using var decryptedData = new System.IO.MemoryStream();
            csDecrypt.CopyTo(decryptedData);
            return decryptedData.ToArray();
        }


        private static byte[] GenerateKeyFromPassword(string password)
        {
            byte[] salt = Encoding.UTF8.GetBytes("salt1234");

            using var deriveBytes = new Rfc2898DeriveBytes(password, salt, 65536);
            return deriveBytes.GetBytes(32); // 256 bits
        }

    }
}
