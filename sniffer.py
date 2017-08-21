import argparse
import glob
import logging
import netifaces as ni
import signal
import socket
import sys
import time

import dpkt

import cflow_parser
import dal

# ##### Globals #####
g_packets_count = 0
g_logger = None


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


def start_sniffing(iface):
    """
    sniffing traffic from a given interface
    """
    # Create UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    ni.ifaddresses(iface)
    ip = ni.ifaddresses(iface)[ni.AF_INET][0]['addr']

    # Bind it to listen to the dedicated netflow port
    sock.bind((ip, cflow_parser.NETFLOW_PORT))

    while True:
        packet, addr = sock.recvfrom(1500)

        # Process packet
        process_packet(time.time(), packet)


def create_app_logger():
    """
    Sets global logger to writing to file
    :return:
    """
    logging.basicConfig(filename='logs/collector.log', level=logging.DEBUG)


if __name__ == '__main__':
    create_app_logger()

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
            logging.info('start reading file: %s' % (f, ))
            # Read file
            read_pcap(f)

    elif args['mode'] == "sniff":
        # Parse the interface name arg
        iface = args['interface']

        start_sniffing(iface)

    # If the mode is non of the above
    else:
        logging.error("only pcap and sniff mode arguments are valid")
        exit(1)
