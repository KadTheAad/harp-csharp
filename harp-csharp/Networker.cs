using System;
using System.Net;
using System.Net.Sockets;

namespace harp_csharp
{
    public static class Networker
    {
        public static bool SendBroadcast(byte[] sendData, int port, IPAddress broadcastAddress)
        {
            try
            {
                using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                socket.EnableBroadcast = true;
                IPEndPoint endPoint = new IPEndPoint(broadcastAddress, port);
                socket.SendTo(sendData, endPoint);
                return true;
            }
            catch (SocketException)
            {
                return false;
            }
        }

        public static (byte[], IPAddress) ReceiveBroadcast(int port, int bufferSize, int timeout)
        {
            try
            {
                using Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
                IPEndPoint endPoint = new IPEndPoint(IPAddress.Any, port);
                socket.Bind(endPoint);
                socket.ReceiveTimeout = timeout;

                byte[] receiveData = new byte[bufferSize];
                EndPoint remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                int receivedBytes = socket.ReceiveFrom(receiveData, ref remoteEndPoint);

                byte[] data = new byte[receivedBytes];
                Array.Copy(receiveData, data, receivedBytes);

                return new (data, ((IPEndPoint)remoteEndPoint).Address);
            }
            catch (SocketException)
            {
                return (null, null);
            }
        }
    }
}