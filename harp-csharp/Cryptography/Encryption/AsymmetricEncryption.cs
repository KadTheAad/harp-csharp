using System.Security.Cryptography;

namespace harp_csharp.Cryptography.Encryption
{
    public class AsymmetricEncryption
    {
        public RSAParameters PublicKey { get; set; }
        private RSAParameters PrivateKey { get; set; }
        public RSAParameters OtherPublicKey { get; set; }

        public AsymmetricEncryption()
        {
            using var rsa = new RSACryptoServiceProvider(2048);
            rsa.PersistKeyInCsp = false;
            PublicKey = rsa.ExportParameters(false);
            PrivateKey = rsa.ExportParameters(true);
        }

        public byte[] Encrypt(byte[] data, RSAParameters publicKey)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(publicKey);
            var cipherText = rsa.Encrypt(data, true);
            return cipherText;
        }

        public byte[] Decrypt(byte[] data)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(PrivateKey);
            var plainText = rsa.Decrypt(data, true);
            return plainText;
        }

        public byte[] Sign(byte[] data)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(PrivateKey);
            var rsaFormatter = new RSAPKCS1SignatureFormatter(rsa);
            rsaFormatter.SetHashAlgorithm("SHA256");
            var signedData = rsaFormatter.CreateSignature(data);
            return signedData;
        }

        public bool Verify(byte[] data, byte[] signature, RSAParameters publicKey)
        {
            using var rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(publicKey);
            var rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("SHA256");
            var isVerified = rsaDeformatter.VerifySignature(data, signature);
            return isVerified;
        }
    }
}