import struct
from socket import inet_ntoa

import dal

HEADER_SIZE = 24
RECORD_SIZE = 48
current = 44


def parse(packet):
    # TODO: add input verification
    # extract version and num of records
    packet = packet[44:]
    (version, count) = struct.unpack('!HH', packet[0:4])

    # if not Netflow V5 - continue
    if version != 5:
        return

    # if number of packets is unusual - continue
    if count <= 0 or count >= 1000:
        return

    # For each record
    for i in range(0, count):
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

        dal.upsert_session(session_data)
