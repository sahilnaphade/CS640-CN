import socket
import struct
import ipaddress
from io import BlockingIOError

def send_packet(packet, destination_host, destination_port, send_socket=None, log_handler=None):
    try:
        if not send_socket:
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_socket.sendto((packet), (destination_host, destination_port))
    except Exception as ex:
        raise ex

def receive_packet(receive_port, receive_socket=None):
    try:
        if not receive_socket:
            receive_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            receive_socket.setblocking(False)
            receive_socket.bind('0.0.0.0', receive_port)
        data, addr = receive_socket.recvfrom(1024)
        return data, addr
    except BlockingIOError as bie:
        pass
    except Exception as ex:
        raise ex

def inner_payload_encapsulate(packet_type, packet_seq_no, payload, payload_length):
    sequence_number_network = socket.htonl(packet_seq_no)
    header = str(packet_type).encode("utf-8") + struct.pack('II', sequence_number_network, payload_length)
    return header + payload.encode("utf-8")

def outer_payload_encapsulate(priority, src_ip_addr, src_port, dest_ip_addr, dest_port, inner_payload):
    src_ip_int = ipaddress.v4_int_to_packed(src_ip_addr)
    dst_ip_int = ipaddress.v4_int_to_packed(dest_ip_addr)
    outer_header = struct.pack("cIhIhI", str(priority).encode('utf-8'), src_ip_int, src_port, dst_ip_int, dest_port, len(inner_payload))
    return outer_header + inner_payload

def inner_payload_decapsulate(inner_packet):
    packet_type = inner_packet[0:1].decode('utf-8')
    header = inner_packet[1:9]
    header = struct.unpack('II', header)
    sequence_number_network = header[0]
    sequence_number = socket.ntohl(sequence_number_network)

    data = inner_packet[9:]
    return packet_type, sequence_number, data

def outer_payload_metadata(packet):
    outer_header = packet[0:17]
    outer_header_unpacked = struct.unpack("<cIhIhI", outer_header)
    priority, src_ip_int, src_port, dst_ip_int, dst_port, length = outer_header_unpacked

    src_ip_addr = ipaddress.ip_address(src_ip_int)
    dst_ip_addr = ipaddress.ip_address(dst_ip_int)
    return priority, src_ip_addr, src_port, dst_ip_addr, dst_port, length


def outer_payload_decapsulate(packet):
    outer_header = packet[0:17]
    outer_header_unpacked = struct.unpack("<cIhIhI", outer_header)
    priority, src_ip_int, src_port, dst_ip_int, dst_port, length = outer_header_unpacked

    src_ip_addr = ipaddress.ip_address(src_ip_int)
    dst_ip_addr = ipaddress.ip_address(dst_ip_int)
    
    packet_type, sequence_number, data = inner_payload_decapsulate(packet[17:])
    
    return priority, src_ip_addr, src_port, dst_ip_addr, dst_port, length, packet_type, sequence_number, data

