using System.Collections.Generic;
using CommandLine;

namespace PacketSniffer
{
    public class Program
    {
        /// <summary>
        /// Defined Options.
        /// </summary>
        public class Options
        {
            [Option('i', "interface", Required = true, HelpText = "Interface to listen on")]
            public string Inter { get; set; }

            [Option('p', "port", HelpText = "Port to listen on")]
            public uint Port { get; set; }

            [Option('t', "tcp", HelpText = "Catch only TCP packets")]
            public bool Tcp { get; set; }

            [Option('u', "udp", HelpText = "Catch only UDP packets")]
            public bool Udp { get; set; }

            [Option('n', "number", Default = 1, HelpText = "Number of packets to catch")]
            public int Count { get; set; }
        }

        private static void Main(string[] args)
        {
            Parser.Default.ParseArguments<Options>(args)
                .WithParsed(RunOptions)
                .WithNotParsed(HandleParseError);
        }

        private static void RunOptions(Options opt)
        {
            //Run sniffing in infinite loop
            while (true)
            {
                Sniffer.Sniff(opt);
            }
        }

        /// <summary>
        /// Error handling of options
        /// </summary>
        /// <param name="errs"></param>
        private static void HandleParseError(IEnumerable<Error> errs) => Sniffer.PrintInterfaces();
    }
}