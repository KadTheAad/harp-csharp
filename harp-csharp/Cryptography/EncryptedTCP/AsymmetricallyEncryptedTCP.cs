using System;
using System.IO;
using System.Net.Sockets;
using harp_csharp.Cryptography.Encryption;

namespace harp_csharp.Cryptography.EncryptedTCP
{
    public class AsymmetricallyEncryptedTCP : IEncryptedTCP
    {
        private readonly AsymmetricEncryption _encryption;
        private readonly BinaryReader _reader;
        private readonly BinaryWriter _writer;

        public AsymmetricallyEncryptedTCP(AsymmetricEncryption encryption, Socket socket)
        {
            _encryption = encryption;

            NetworkStream stream = new NetworkStream(socket);
            _reader = new BinaryReader(stream);
            _writer = new BinaryWriter(stream);
        }

        public bool Send(byte[] data)
        {
            try
            {
                byte[] encrypted = _encryption.Encrypt(data, _encryption.OtherPublicKey);
                _writer.Write(encrypted.Length);
                _writer.Write(encrypted);
                _writer.Flush();
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return false;
            }
        }

        public byte[] Receive()
        {
            try
            {
                int length = _reader.ReadInt32();
                byte[] data = _reader.ReadBytes(length);
                return _encryption.Decrypt(data);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }
    }
}