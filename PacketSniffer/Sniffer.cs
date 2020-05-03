using System;
using System.Linq;
using PacketDotNet;
using SharpPcap;

namespace PacketSniffer
{
    public static class Sniffer
    {
        /// <summary>
        /// Prints all available interfaces
        /// </summary>
        public static void PrintInterfaces()
        {
            Console.WriteLine("Available interfaces:");
            var devices = CaptureDeviceList.Instance;
            foreach (var device in devices)
            {
                Console.WriteLine($"{device.Name}: {device.Description}");
            }
        }

        /// <summary>
        /// Method handles packets
        /// </summary>
        /// <param name="opt"></param>
        public static void Sniff(Program.Options opt)
        {
            //Try to find the specified interface. If correct is not found or more interfaces with the same name exits
            //application exits with Non-zero exit code
            ICaptureDevice device = null;
            try
            {
                device = CaptureDeviceList.Instance.Single(x => x.Name == opt.Inter);
            }
            catch (Exception)
            {
                Console.WriteLine("None or more interfaces with the name exists " + opt.Inter);
                Environment.Exit(1);
            }

            uint numberOfProcessedPackets = 0;
            //Try to open the interface. If it fails write message and exit with code 2
            try
            {
                device.Open();
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
                Environment.Exit(2);
            }

            RawCapture packet;
            bool both = !opt.Tcp && !opt.Udp;
            while ((packet = device.GetNextPacket()) != null)
            {
                //Check number of processed packets
                if (numberOfProcessedPackets >= opt.Count)
                    break;

                var time = packet.Timeval.Date;
                var packetInfo = Packet.ParsePacket(packet.LinkLayerType, packet.Data);

                //Packet extraction
                var ipPacket = packetInfo.Extract<IPPacket>();

                var udpPacket = packetInfo.Extract<UdpPacket>();
                var tcpPacket = packetInfo.Extract<TcpPacket>();

                //Packet resolving
                if (opt.Tcp || both)
                {
                    if (opt.Port == 0)
                        PacketPrinter.Print(time, ipPacket, tcpPacket);
                    else if (opt.Port == tcpPacket?.SourcePort || opt.Port == tcpPacket?.DestinationPort)
                        PacketPrinter.Print(time, ipPacket, tcpPacket);
                }

                if (opt.Udp || both)
                {
                    if (opt.Port == 0)
                        PacketPrinter.Print(time, ipPacket, udpPacket);
                    else if (opt.Port == tcpPacket?.SourcePort || opt.Port == tcpPacket?.DestinationPort)
                        PacketPrinter.Print(time, ipPacket, udpPacket);
                }

                ++numberOfProcessedPackets;
            }
        }
    }
}