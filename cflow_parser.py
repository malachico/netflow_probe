import socket, struct

from socket import inet_ntoa

import dpkt

import dal

HEADER_SIZE = 24
RECORD_SIZE = 48
current = 44

def parse(timestamp, packet):
    # Parse the input
    eth_frame = dpkt.ethernet.Ethernet(packet)

    # If not IP return
    if eth_frame.type != dpkt.ethernet.ETH_TYPE_IP:
        return

    # extract version and num of records
    packet = packet[44:]
    (version, count) = struct.unpack('!HH', packet[0:4])

    # if not Netflow V5 - continue
    if version != 5:
        return

    # if number of packets is unusual - continue
    if count <= 0 or count >= 1000:
        return

    # Current time in milliseconds since the export device booted
    uptime = socket.ntohl(struct.unpack('I', packet[4:8])[0])

    # Current count of seconds since 0000 UTC 1970
    epochseconds = socket.ntohl(struct.unpack('I', packet[8:12])[0])

    # For each record
    for i in range(0, count):
        try:
            # Point the current record
            base = HEADER_SIZE + (i * RECORD_SIZE)

            # Unpack its data
            data = struct.unpack('!IIIIHH', packet[base + 16:base + 36])

            # Extract the data to dict
            session_data = \
                {'src_ip': inet_ntoa(packet[base + 0:base + 4]),
                 'dest_ip': inet_ntoa(packet[base + 4:base + 8]),
                 'packets_count': data[0],
                 'bytes_count': data[1],
                 'start_time': data[2],
                 'end_time': data[3],
                 'src_port': data[4],
                 'dest_port': data[5],
                 'protocol': ord(packet[base + 38])}
        except:
            continue

        assert session_data is not None

        dal.upsert_session(session_data)
