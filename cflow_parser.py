import socket, struct

from socket import inet_ntoa

import dal

SIZE_OF_HEADER = 24
SIZE_OF_RECORD = 48

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', 4739))


HEADER_SIZE = 24
RECORD_SIZE = 48

while True:
    buf, addr = sock.recvfrom(1500)

    # extract version and num of records
    (version, count) = struct.unpack('!HH', buf[0:4])  # if not Netflow V5 - continue
    if version != 5:
        continue

    # if number of packets is unusual - continue
    if count <= 0 or count >= 1000:
        continue

    # Current time in milliseconds since the export device booted
    up_time = socket.ntohl(struct.unpack('I', buf[4:8])[0])

    # Current count of seconds since 0000 UTC 1970
    timestamp = socket.ntohl(struct.unpack('I', buf[8:12])[0])

    # For each record
    for i in range(0, count):
        try:
            # Point the current record
            base = HEADER_SIZE + (i * RECORD_SIZE)

            # Unpack its data
            data = struct.unpack('!IIIIHH', buf[base + 16:base + 36])

            # Extract the data to dict
            session_data = \
                {'src_ip': inet_ntoa(buf[base + 0:base + 4]),
                 'dest_ip': inet_ntoa(buf[base + 4:base + 8]),
                 'packets_count': data[0],
                 'bytes_count': data[1],
                 'start_time': data[2],
                 'end_time': data[3],
                 'src_port': data[4],
                 'dest_port': data[5],
                 'protocol': ord(buf[base + 38])}
        except:
            continue

    assert session_data is not None

    dal.upsert_session(session_data)
