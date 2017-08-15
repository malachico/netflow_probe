# Netflow V5 Collector

This is a Netflow V5 Collector.

It expects receiving netflow V5 traffic from exporter, parses it, and insert to sessions data to MongoDB.

modes:
sniffs traffic from a given interface
reads packets from pcap file


### usage:
python sniffer.py [-h] [-m MODE] [-i INTERFACE] [-f FILE]

#### usege examples:

##### sniff mode:
python sniffer.py -m sniff -i eth0

##### pcap mode:
python sniffer.py -m pcap -f *.pcap

##### help:
-m, --mode: mode of capturing: sniff | pcap
-i, --interface, interface to sniff from when in sniff mode
-f, --file, file to capture when in pcap mode

TODO:
Add packet verification to cflow_parser.py in method parse.

