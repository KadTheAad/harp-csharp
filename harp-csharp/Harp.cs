using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using harp_csharp.Cryptography;
using harp_csharp.Cryptography.EncryptedTCP;
using harp_csharp.Cryptography.Encryption;

namespace harp_csharp
{
    public class Harp
    {
        private const int BufferSize = 8192;
        private const int Port = 4545;
        private const int Port2 = 8192;

        private readonly string _password;
        private readonly byte[] _to;
        private readonly byte[] _me;
        private readonly bool _isSender;
        private readonly List<Thread> _threads;
        private volatile bool _done;
        private readonly AsymmetricEncryption _key;
        private readonly Dictionary<IPAddress, List<long>> _addresses = new();
        private readonly HarpCallback _callback;

        public Harp(bool isSender, byte[] to, byte[] me, string password,
            HarpCallback callback)
        {
            Debug.WriteLine("Initializing Harp...");
            _isSender = isSender;
            _to = to;
            _me = me;
            _password = password;
            _callback = callback;

            _done = false;
            _threads = new List<Thread>();
            _key = new AsymmetricEncryption();
        }

        public void Run()
        {
            Debug.WriteLine("Running Harp...");
            if (_isSender)
            {
                StartTask(new Thread(SendBroadcastPackets));
                StartTask(new Thread(ListenForRepliesToBroadcast));
            }
            else
            {
                StartTask(new Thread(ListenForBroadcastsAndReply));
            }
        }

        private void SendBroadcastPackets()
        {
            Debug.WriteLine("Sending broadcast packets...");
            try
            {
                int i = 0;
                byte[] packetAsBytes = null;
                while (!_done)
                {
                    packetAsBytes = CreatePacket(i, packetAsBytes);
                    byte[] finalPacketAsBytes = packetAsBytes;
                    StartTask(new Thread(() => Networker.SendBroadcast(ConcatenateByteArrays(finalPacketAsBytes, new byte[] { 1 }),
                        Port, IPAddress.Broadcast)));
                    i = i == 5 ? 0 : i + 1;
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Exception in SendBroadcastPackets: {e}");
            }
        }

        private byte[] CreatePacket(int i, byte[] packet)
        {
            Debug.WriteLine("Creating packet...");
            if (packet == null || i == 5)
                return new VerifyPacket(_to, _me, _password, _key).Get();
            Thread.Sleep(1000);
            return packet;
        }

        private void ListenForRepliesToBroadcast()
        {
            try
            {
                // var hostName = Dns.GetHostName();
                // IPHostEntry localhost = Dns.GetHostEntry(hostName);
                // IPAddress localIpAddress = localhost.AddressList[0];
                //
                // Console.WriteLine(localIpAddress);
                IPEndPoint ipEndPoint = new IPEndPoint(IPAddress.Any, Port2);
                using Socket server = new(
                    ipEndPoint.AddressFamily,
                    SocketType.Stream,
                    ProtocolType.Tcp);
                if (!server.IsBound)
                {
                    server.Bind(ipEndPoint);
                }
                server.Listen(100);
                Debug.WriteLine("Listening for replies to broadcast...");
                while (!_done)
                {
                    Debug.WriteLine("Accepting...");
                    var accepted = server.Accept();
                    Debug.WriteLine("Accepted...");

                    IEncryptedTCP encryptedTcp = new SymmetricallyEncryptedTCP(_password, accepted);

                    StartTask(new Thread(() => HandleReplyToBroadcast(encryptedTcp, accepted)));
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Exception in ListenForRepliesToBroadcast: {e}");
            }
        }

        private void HandleReplyToBroadcast(IEncryptedTCP encryptedTcp, Socket accepted)
        {
            Debug.WriteLine("Handling reply to broadcast...");
            try
            {
                // Receive verify packet
                byte[] data = encryptedTcp.Receive();
                if (data == null) return;
                VerifyPacket verifyPacket = new VerifyPacket(data);
                if (!verifyPacket.Verify(VerifyPacket.GetStarter(_me, _to, _password))) return;

                // Send public key
                if (!encryptedTcp.Send(PublicKeyManager.PublicKeyToByteArray(_key.PublicKey))) return;
                // Receive public key
                byte[] publicKey = encryptedTcp.Receive();
                if (publicKey == null) return;
                _key.OtherPublicKey = PublicKeyManager.ByteArrayToPublicKey(publicKey);

                if (!_key.Verify(verifyPacket.GetStarter(), verifyPacket.GetSignature(), _key.OtherPublicKey))
                    return;

                Finished(((IPEndPoint)accepted.RemoteEndPoint).Address);
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Exception in HandleReplyToBroadcast: {e}");
            }
        }

        private void ListenForBroadcastsAndReply()
        {
            Debug.WriteLine("Listening for broadcasts and reply...");
            try
            {
                byte[] starter = VerifyPacket.GetStarter(_me, _to, _password);
                while (!_done)
                {
                    (byte[], IPAddress) data;
                    try
                    {
                        data = Networker.ReceiveBroadcast(Port, BufferSize, 1000);
                    }
                    catch (Exception e)
                    {
                        Debug.WriteLine($"Exception in ListenForBroadcastsAndReply: {e}");
                        continue;
                    }

                    if (data.Item1 == null) continue;

                    StartTask(new Thread(() => ReplyToBroadcast(data.Item1, data.Item2, starter)));
                }
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Exception in ListenForBroadcastsAndReply: {e}");
            }
        }

        private void ReplyToBroadcast(byte[] data, IPAddress address, byte[] starter)
        {
            Debug.WriteLine("Replying to broadcast...");
            try
            {
                if (_addresses.ContainsKey(address))
                {
                    if (_addresses[address].Count > 5) return;
                    if (_addresses[address][_addresses.Count-1] < Hasher.Timestamp() - 7000)
                    {
                        _addresses[address].Add(Hasher.Timestamp());
                    }
                    else
                    {
                        Debug.WriteLine("Received too many packets from the same address. Ignoring...");
                        return;
                    }
                }
                else
                {
                    List<long> list = new List<long> { Hasher.Timestamp() };
                    _addresses.Add(address, list);
                }
                
                Debug.WriteLine($"Received broadcast from {address}");
                Debug.WriteLine($"Received data {data}");

                if (data == null) return;

                while (data[data.Length - 1] == 0)
                {
                    byte[] temp = new byte[data.Length - 1];
                    Array.Copy(data, 0, temp, 0, temp.Length);
                    data = temp;
                }

                byte[] temp2 = new byte[data.Length - 1];
                Array.Copy(data, 0, temp2, 0, temp2.Length);
                data = temp2;

                VerifyPacket packet = new VerifyPacket(data);
                
                Debug.WriteLine($"Created packet {packet}");
                Debug.WriteLine($"Packet starter: {packet.GetStarter()}");
                Debug.WriteLine($"Starter: {starter}");
                Debug.WriteLine($"Packet signature: {packet.GetSignature()}");
                Debug.WriteLine($"Packet get: {packet.Get()}");
                Debug.WriteLine($"Packet from: {packet.GetFrom()}");
                Debug.WriteLine($"Packet to: {packet.GetTo()}");
                Debug.WriteLine($"Packet timestamp: {packet.GetTimestamp()}");
                Debug.WriteLine($"Packet pow: {packet.GetProofOfWork()}");
                Debug.WriteLine($"Packet pow valid: {packet.ValidateProofOfWork()}");
                Debug.WriteLine($"Packet signature valid: {packet.Verify(starter)}");
                

                if (!packet.Verify(starter)) return;
                
                Debug.WriteLine($"Packet verified {packet}");

                if (_callback == null)
                    Console.WriteLine($"Received valid message from {address}");
                else
                    _callback.Phase2(address, new VerifyPacket(packet));
                Phase2(address, packet);
            }
            catch (Exception e)
            {
                Debug.WriteLine($"Exception in ReplyToBroadcast: {e}");
            }
        }

        private void Phase2(IPAddress address, VerifyPacket packet)
        {
            Debug.WriteLine("Phase 2...");
            if (_isSender) return;

            void Start()
            {
                try
                {
                    using var socket = new Socket(SocketType.Stream, ProtocolType.Tcp);
                    // Send verify packet back
                    byte[] packetAsBytes = new VerifyPacket(_to, _me, _password, _key).Get();
                    socket.Connect(new IPEndPoint(address, Port2));
                    Debug.WriteLine($"Connected to {address}");
                    IEncryptedTCP encryptedTcp = new SymmetricallyEncryptedTCP(_password, socket);
                    if (!encryptedTcp.Send(packetAsBytes))
                    {
                        Debug.WriteLine("Failed to send verify packet back");
                        return;
                    }

                    // Receive public key
                    byte[] publicKey = encryptedTcp.Receive();
                    if (publicKey == null) return;
                    _key.OtherPublicKey = PublicKeyManager.ByteArrayToPublicKey(publicKey);

                    // Send public key back
                    if (!_key.Verify(packet.GetStarter(), packet.GetSignature(), _key.OtherPublicKey)) return;
                    if (!encryptedTcp.Send(PublicKeyManager.PublicKeyToByteArray(_key.PublicKey))) return;
                    Finished(address);
                }
                catch (Exception e)
                {
                    Debug.WriteLine($"Exception in Phase2: {e}");
                }
            }

            StartTask(new Thread( Start));
        }

        private void Finished(IPAddress address)
        {
            if (_done) return;
            _done = true;
            Debug.WriteLine($"Finished: {address}");
            if (_callback == null)
                Console.WriteLine($"Finished: {address}");
            else
                _callback.Run(address);

            Task.Run(() =>
            {
                foreach (var thread in _threads)
                {
                    try
                    {
                        thread.Abort();
                    }
                    catch (AggregateException) { }

                    if (thread.IsAlive)
                    {
                        Debug.WriteLine($"Thread {thread.Name} is still running...");
                    }
                }
            });
        }

        private void StartTask(Thread thread)
        {
            Debug.WriteLine("Starting task...");
            thread.Start();
            _threads.Add(thread);
        }

        public static byte[] ConcatenateByteArrays(byte[] a, byte[] b)
        {
            Debug.WriteLine("Concatenating byte arrays...");
            byte[] result = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, result, 0, a.Length);
            Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
            return result;
        }
    }
}