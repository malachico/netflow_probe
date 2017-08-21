import struct
from socket import inet_ntoa

import logging

import dal
import json_client

HEADER_SIZE = 24
RECORD_SIZE = 48
current = 44
NETFLOW_PORT = 4739


def parse(timestamp, packet):
    # extract version and num of records
    (version, count) = struct.unpack('!HH', packet[0:4])

    uptime = struct.unpack('!I', packet[4:8])[0]

    # if not Netflow V5 - continue
    if version != 5:
        return

    # verify num of records
    if count <= 0 or count > 30:
        return

    # For each record
    for i in range(0, count):
        # Point the current record
        base = HEADER_SIZE + (i * RECORD_SIZE)

        # Unpack data
        data = struct.unpack('!IIIIHH', packet[base + 16:base + 36])

        # Extract the data to dict
        session_data = \
            {'src_ip': inet_ntoa(packet[base + 0:base + 4]),
             'dest_ip': inet_ntoa(packet[base + 4:base + 8]),
             'packets_count': data[0],
             'bytes_count': data[1],
             # epoch time now - time of the machine uptime + start time of the session since the machine up
             'start_time': timestamp - uptime + data[2],
             'end_time': timestamp - uptime + data[3],
             'src_port': data[4],
             'dest_port': data[5],
             'tcp_flags': ord(packet[base + 37]),
             'protocol': ord(packet[base + 38])}

        # Log session
        logging.info("session parsed : %s" % (session_data, ))

        # Upsert session in DB
        dal.upsert_session(session_data)

        # Send session data to server
        json_client.send_json_to_server(session_data)
