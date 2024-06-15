using System;
using System.IO;
using System.Net.Sockets;
using harp_csharp.Cryptography.Encryption;

namespace harp_csharp.Cryptography.EncryptedTCP
{
    public class SymmetricallyEncryptedTCP : IEncryptedTCP
    {
        private readonly string _password;
        private readonly BinaryReader _reader;
        private readonly BinaryWriter _writer;

        public SymmetricallyEncryptedTCP(string password, Socket socket)
        {
            _password = password;

            NetworkStream stream = new NetworkStream(socket);
            _reader = new BinaryReader(stream);
            _writer = new BinaryWriter(stream);
        }

        public bool Send(byte[] data)
        {
            try
            {
                byte[] encrypted = SymmetricEncryption.Encrypt(data, _password);
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
                return SymmetricEncryption.Decrypt(data, _password);
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return null;
            }
        }
    }
}