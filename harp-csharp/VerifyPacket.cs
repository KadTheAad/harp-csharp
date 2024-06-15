using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Text;
using harp_csharp.Cryptography;
using harp_csharp.Cryptography.Encryption;

namespace harp_csharp
{
    public class VerifyPacket
    {
        private readonly byte[] _to;
        private readonly byte[] _from;
        private readonly string _password;
        private readonly long _proofOfWork;
        private readonly byte[] _signature;
        private readonly long _timestamp;
        private readonly byte[] _starter;

        public VerifyPacket(VerifyPacket packet)
        {
            _to = packet._to;
            _from = packet._from;
            _password = packet._password;
            _proofOfWork = packet._proofOfWork;
            _signature = packet._signature;
            _timestamp = packet._timestamp;
            _starter = packet._starter;
        }

        public VerifyPacket(byte[] to, byte[] from, string password, AsymmetricEncryption key)
        {
            _to = to;
            _from = from;
            _password = password;
            
            _starter = GetStarter(to, from, password);

            try
            {
                _signature = key.Sign(_starter);
            }
            catch (Exception e)
            {
                throw new Exception(e.Message);
            }

            _timestamp = Hasher.Timestamp();

            _proofOfWork = ProofOfWork.Get(_starter, _signature, _timestamp);
            // Console.WriteLine(_proofOfWork);
            // Console.WriteLine(new Hasher().HashBytes(ProofOfWork.GetMessage(_starter, _signature, _timestamp)));
            // Console.WriteLine(ProofOfWork.Verify(_starter, _signature, _timestamp, _proofOfWork));
            // long x = ProofOfWork.Get(GetStarter(), GetSignature(), GetTimestamp());
            // Console.WriteLine(x);
            // Console.WriteLine(new Hasher().HashBytes(ProofOfWork.GetMessage(GetStarter(), GetSignature(), GetTimestamp())));
            // Console.WriteLine(ProofOfWork.Verify(GetStarter(), GetSignature(), GetTimestamp(), x));
        }

        public VerifyPacket(byte[] received)
        {
            _to = null;
            _from = null;
            _password = null;

            using MemoryStream ms = new MemoryStream(received);
            using BinaryReader br = new BinaryReader(ms);
            int starterLength = br.ReadInt32();
            _starter = br.ReadBytes(starterLength);

            int signatureLength = br.ReadInt32();
            _signature = br.ReadBytes(signatureLength);

            _proofOfWork = br.ReadInt64();
            _timestamp = br.ReadInt64();
        }

        public bool ValidateProofOfWork()
        {
            return ProofOfWork.Verify(GetStarter(), GetSignature(), GetTimestamp(), GetProofOfWork());
        }

        public bool Verify(byte[] starter)
        {
            if (!_starter.SequenceEqual(starter)) return false;
            if (!ValidateProofOfWork()) return false;
            return Hasher.Timestamp() - _timestamp <= 16000 && Hasher.Timestamp() - _timestamp >= 0;
        }

        public byte[] Get()
        {
            using MemoryStream ms = new MemoryStream();
            using (BinaryWriter bw = new BinaryWriter(ms))
            {
                bw.Write(_starter.Length);
                bw.Write(_starter);
                bw.Write(_signature.Length);
                bw.Write(_signature);
                bw.Write(_proofOfWork);
                bw.Write(_timestamp);
                bw.Flush();
            }
            return ms.ToArray();
        }

        public byte[] GetStarter()
        {
            return _starter;
        }

        public static byte[] GetStarter(byte[] to, byte[] from, string password)
        {
            Hasher hasher = new Hasher();

            byte[] toHased = hasher.Hash(to);
            byte[] fromHased = hasher.Hash(from);
            byte[] toFromHased = hasher.Hash(Harp.ConcatenateByteArrays(toHased, fromHased));
            byte[] passwordHased = hasher.Hash(Encoding.UTF8.GetBytes(password));

            int buffer = passwordHased.Length;

            byte[] starter = new byte[buffer];

            int i = 0;
            foreach (byte b in toHased)
                starter[i] = (byte)(b ^ fromHased[i++]);

            i = 0;
            foreach (byte b in starter)
                starter[i] = (byte)(b ^ passwordHased[i++]);

            i = 0;
            foreach (byte b in starter)
                starter[i] = (byte)(b ^ toFromHased[i++]);

            return hasher.Hash(starter);
        }

        public byte[] GetTo()
        {
            return _to;
        }

        public byte[] GetFrom()
        {
            return _from;
        }

        public long GetProofOfWork()
        {
            return _proofOfWork;
        }

        public byte[] GetSignature()
        {
            return _signature;
        }

        public long GetTimestamp()
        {
            return _timestamp;
        }
    }
}