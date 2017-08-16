import socket
import json

SERVER_IP_PORT = "10.0.0.9", 8585


def convert_message(session_data):
    """
    Convert message to server format

    :param session_data:
    :return:
    """
    return {
        'size': str(session_data['bytes_count']),
        'timestamp': str(session_data['start_time']),
        'srcip': str(session_data['src_ip']),
        'dstip': str(session_data['dest_ip']),
        'srcport': str(session_data['src_port']),
        'dstport': str(session_data['dest_port']),
        'flags': str(session_data['tcp_flags']),
    }


def send_json_to_server(message):
    """
    given a dictionary to send to server, send it in json format via UDP socket
    :param message:
    :return:
    """

    # Convert message to server format
    message = convert_message(message)

    # serialize the dictionary
    serialized = json.dumps(message)

    # Create a UDP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # send the message to server
    sock.sendto(serialized, SERVER_IP_PORT)
