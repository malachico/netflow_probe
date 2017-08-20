import argparse
import glob
import pcapy
import signal
import sys
import time

import dpkt
import socket
import cflow_parser
import dal

# ##### Globals #####
g_packets_count = 0


# ##### Functions #####
def signal_handler(signal, frame):
    print '\nCtrl+C was pressed. Exit gracefully.'
    sys.exit(0)


# Sign the ctrl+C signal to exit gracefully.
signal.signal(signal.SIGINT, signal_handler)


def process_packet(timestamp, packet):
    count_packet()
    cflow_parser.parse(timestamp, packet)


def read_pcap(file_to_read):
    # Read pcap file
    pcap_file = open(file_to_read)

    # pcap_reader is a reader pcap file object
    pcap_reader = dpkt.pcap.Reader(pcap_file)

    # Read all packets to list of tuples: (timestamp, packet)
    packets_list = [(ts, packet) for ts, packet in pcap_reader]

    # Process all packets in list
    map(lambda ts_packet: process_packet(ts_packet[0], ts_packet[1]), packets_list)


def count_packet():
    """
    count the packets which read and print if necessary
    :return:
    """
    global g_packets_count

    g_packets_count += 1

    if g_packets_count % 10000 == 0:
        print "read %s packets" % (g_packets_count,)


def start_sniffing(interface):
    """
    sniffing traffic from a given interface
    """
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Bind it to listen to the dedicated netflow port
    sock.bind(('0.0.0.0', cflow_parser.NETFLOW_PORT))

    while True:
        packet, addr = sock.recvfrom(1500)

        # Process packet
        process_packet(time.time(), packet)

if __name__ == '__main__':

    # Parse args
    parser = argparse.ArgumentParser()
    parser.add_argument('-m', '--mode', help='mode of capturing: sniff | pcap', required=True)
    parser.add_argument('-i', '--interface', help='interface to sniff from when in sniff mode', required=False)
    parser.add_argument('-f', '--file', help='file to capture when in pcap mode', required=False)

    args = vars(parser.parse_args())

    # Init DB
    dal.init_db()

    # get mode : pcap file reader or sniffing
    mode = sys.argv[1]

    if args['mode'] == "pcap":
        # Parse the pcap filename arg
        pcap_files = glob.glob(args['file'])

        pcap_files.sort()

        for f in pcap_files:
            print 'start reading file:', f
            # Read file
            read_pcap(f)

    elif args['mode'] == "sniff":
        # Parse the interface name arg
        interface = args['interface']

        start_sniffing(interface)

    # If the mode is non of the above
    else:
        print "only pcap and sniff mode arguments are valid"
        exit(1)
