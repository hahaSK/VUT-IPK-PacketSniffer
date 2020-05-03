using System;
using System.Linq;
using System.Net;
using PacketDotNet;

namespace PacketSniffer
{
    /// <summary>
    /// Packet sniffer class that handles packet printing
    /// </summary>
    public static class PacketPrinter
    {
        /// <summary>
        /// Prints the packet to output.
        /// </summary>
        /// <param name="time">packet time value</param>
        /// <param name="ipPacket"><see cref="IPPacket"/> class instance which holds IP address of source and destination.</param>
        /// <param name="packet">Packet to print</param>
        public static void Print(DateTime time, IPPacket ipPacket, TransportPacket packet)
        {
            //If packet is empty don't print it
            if (packet == null)
                return;

            var srcHostName = GetDomainName(ipPacket.SourceAddress);
            var destHostName = GetDomainName(ipPacket.DestinationAddress);

            //Write the packet time source host name : packet > destination host name : port
            Console.WriteLine(
                $"{time.Hour}:{time.Minute}:{time.Second}.{time.Millisecond} {srcHostName} : {packet.SourcePort} > {destHostName} : {packet.DestinationPort}");
            Console.WriteLine();

            uint byteCount = 0;
            //Write header
            PrintPacket(packet.HeaderData, ref byteCount);
            Console.WriteLine();
            //Write payload
            PrintPacket(packet.PayloadData, ref byteCount);
            Console.WriteLine();
        }

        /// <summary>
        /// Method handles printing data of packets
        /// </summary>
        /// <param name="data"></param>
        /// <param name="byteCount"></param>
        private static void PrintPacket(byte[] data, ref uint byteCount)
        {
            //Group the data into batches, where each batch holds 16 bytes
            var batches = data.Select((x, i) => new {Index = i, Value = x})
                .GroupBy(x => x.Index / 16)
                .Select(x => x.Select(v => v.Value).ToArray())
                .ToArray();

            //Iterate over the batches
            foreach (var batch in batches)
            {
                //Write number of printed bytes
                WriteCount(byteCount);
                int half = 8, bytesInLine = 0;
                bool spaceApplied = false;
                foreach (var b in batch)
                {
                    //Put a space in half of the hex part
                    if (bytesInLine == half)
                    {
                        Console.Write(" ");
                        spaceApplied = true;
                    }

                    //Convert by to hex
                    string s = b.ToString("X");
                    //If hex is single digit prepend 0
                    if (s.Length == 1)
                        s = "0" + s;
                    //Write hex
                    Console.Write(s.ToLower() + " ");

                    ++bytesInLine;
                    ++byteCount;
                }

                //if the batch is not full fill the rest with blank spaces (Padding)
                int empty = 16 - batch.Length;
                for (int i = 0; i < empty; ++i)
                {
                    Console.Write("   ");
                }

                //If space was not applied before apply it (this is for padding)
                if (!spaceApplied)
                    Console.Write(" ");

                bytesInLine = 0;
                //Write bytes in ascii
                foreach (var b in batch)
                {
                    //Put a space in half
                    if (bytesInLine == half)
                        Console.Write(" ");

                    //Convert to char or . if not possible
                    var c = Convert.ToChar(b);
                    if (c > 127)
                        Console.Write('.');
                    else if (char.IsControl(c))
                        Console.Write('.');
                    else
                        Console.Write(c);

                    ++bytesInLine;
                }

                Console.Write('\n');
            }
        }

        /// <summary>
        /// Method writes number of wrote bytes
        /// </summary>
        /// <param name="byteCount"></param>
        private static void WriteCount(in uint byteCount)
        {
            var prependZeros = 4 - byteCount.ToString("X").Length;
            var count = "";
            for (int i = 0; i < prependZeros; ++i)
                count += "0";

            Console.Write($"0x{count}{byteCount:X}: ");
        }

        /// <summary>
        /// Method tries to get domain name from IP address. If not possible the IP address is returned.
        /// </summary>
        /// <param name="ipAddress"><see cref="IPAddress"/> class instance</param>
        /// <returns>domain name.</returns>
        private static string GetDomainName(IPAddress ipAddress)
        {
            try
            {
                return Dns.GetHostEntry(ipAddress).HostName;
            }
            catch
            {
                return ipAddress.ToString();
            }
        }
    }
}