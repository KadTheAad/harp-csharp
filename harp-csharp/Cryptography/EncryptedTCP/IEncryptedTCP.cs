namespace harp_csharp.Cryptography.EncryptedTCP
{
    public interface IEncryptedTCP
    {
        public bool Send(byte[] data);
        public byte[] Receive();
    }
}