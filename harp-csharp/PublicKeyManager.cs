using System.IO;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;

namespace harp_csharp
{
    public static class PublicKeyManager
    {
        public static byte[] PublicKeyToByteArray(RSAParameters publicKey)
        {
            var formatter = new BinaryFormatter();
            using var stream = new MemoryStream();
            formatter.Serialize(stream, publicKey);
            return stream.ToArray();
        }

        public static RSAParameters ByteArrayToPublicKey(byte[] byteArray)
        {
            var formatter = new BinaryFormatter();
            using var stream = new MemoryStream(byteArray);
            return (RSAParameters)formatter.Deserialize(stream);
        }
    }
}