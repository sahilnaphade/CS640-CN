import socket
import struct
import ipaddress
from io import BlockingIOError

PACKET_TYPE_HELLO = "H"
PACKET_TYPE_LINK_STATE = "L"
PACKET_TYPE_ROUTE_TRACE = "T"
PACKET_TYPE_ROUTE_TRACE_REPLY = "Y"

DESTINATION = 0
NEXT_HOP = 1
COST = 2
FWD_TABLE_VALID_IDX = 3

def send_packet(packet, destination_host, destination_port, send_socket=None, log_handler=None):
    try:
        if not send_socket:
            send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_socket.sendto((packet), (destination_host, int(destination_port)))
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
    # print(f"BEFORE HTONL: {packet_seq_no}")
    sequence_number_network = socket.htonl(packet_seq_no)
    # print(f"AFTER HTONL: {sequence_number_network}")
    # print(payload_length)
    packet = str(packet_type).encode("utf-8") + struct.pack('II', sequence_number_network, payload_length) + payload.encode('utf-8')
    # print(type(packet))
    return packet

def outer_payload_encapsulate(src_ip_addr, src_port, dest_ip_addr, dest_port, inner_payload, priority=1):
    if isinstance(src_ip_addr, str):
        src_ip_addr = int(ipaddress.ip_address(src_ip_addr))
    if isinstance(dest_ip_addr, str):
        dest_ip_addr = int(ipaddress.ip_address(dest_ip_addr))
    outer_header = struct.pack("<cIhIhI", str(priority).encode('utf-8'), src_ip_addr, int(src_port), dest_ip_addr, int(dest_port), len(inner_payload))
    return outer_header + inner_payload

def inner_payload_decapsulate(inner_packet):
    packet_type = inner_packet[0:1].decode('utf-8')
    header = inner_packet[1:9]
    header = struct.unpack('II', header)
    sequence_number_network = header[0]
    length = header[1]
    sequence_number = socket.ntohl(sequence_number_network)

    data = inner_packet[9:]
    return packet_type, sequence_number, length, data

def outer_payload_metadata(packet):
    outer_header = packet[0:17]
    outer_header_unpacked = struct.unpack("<cIhIhI", outer_header)
    priority, src_ip_int, src_port, dst_ip_int, dst_port, length = outer_header_unpacked

    src_ip_addr = str(ipaddress.ip_address(src_ip_int))
    dst_ip_addr = str(ipaddress.ip_address(dst_ip_int))
    return priority, src_ip_addr, src_port, dst_ip_addr, dst_port, length


def outer_payload_decapsulate(packet):
    outer_header = packet[0:17]
    outer_header_unpacked = struct.unpack("<cIhIhI", outer_header)
    priority, src_ip_int, src_port, dst_ip_int, dst_port, length = outer_header_unpacked

    src_ip_addr = str(ipaddress.ip_address(src_ip_int))
    dst_ip_addr = str(ipaddress.ip_address(dst_ip_int))
    
    packet_type, sequence_number, inner_length, data = inner_payload_decapsulate(packet[17:])
    
    return priority.decode('utf-8'), src_ip_addr, src_port, dst_ip_addr, dst_port, length, packet_type, sequence_number, inner_length, data

def get_next_hop(source, destination, predecessors):
    # Get the next hop in the path from source to destination
    current_node = destination
    while predecessors[current_node] != source:
        current_node = predecessors[current_node]
    return current_node


def build_forward_table(topology):
    # Dijkstra's algorithm to build the forwarding table
    forward_table = {}
    for node in topology:
        distances, predecessors = dijkstra(node, topology)
        for destination, cost in distances.items():
            if destination != node:
                nexthop = get_next_hop(node, destination, predecessors)
                if node not in forward_table:
                    forward_table[node] = {}
                forward_table[node][destination] = nexthop
    return forward_table

def dijkstra(source, graph):
    # Dijkstra's algorithm to calculate shortest paths
    distances = {node: float('inf') for node in graph}
    predecessors = {node: None for node in graph}
    distances[source] = 0

    unvisited_nodes = set(graph.keys())

    while unvisited_nodes:
        current_node = min(unvisited_nodes, key=lambda node: distances[node])
        unvisited_nodes.remove(current_node)

        for neighbor, cost in graph[current_node]:
            potential_distance = distances[current_node] + cost
            if potential_distance < distances[neighbor]:
                distances[neighbor] = potential_distance
                predecessors[neighbor] = current_node

    return distances, predecessors


"""
We will format the link state vector as follows:
    IP_1:Port_1:cost1|IP_2:Port_2:cost2|...
    Since we get this information from another emulator about its adjacent nodes/connections
    that emulator will be our next hop for this destination
"""

def generate_link_state_vector(fwd_table):
    encoded_vector = []
    for entry in fwd_table:
        encoded_vector.append(entry[DESTINATION][0] + ":" + str(entry[DESTINATION][1]) + ":" + str(entry[COST]))
    final_str = "|".join(encoded_vector)
    return final_str

def decode_link_state_vector(packet_inner_data):
    link_state_vector = []
    lsv = packet_inner_data.decode('utf-8')
    ip_port_cost_pairs = lsv.split("|")
    for each_pair in ip_port_cost_pairs:
        dest_ip_addr, dest_port, dest_cost = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port), int(dest_cost) if dest_cost != "None" else None])
    return link_state_vector

"""
FOR the route trace
We will format the link state vector as follows:
    Dest_IP_1:Dest_port_1|Dest_IP_2:Dest_port_2
    Since we get this information from another emulator about its adjacent nodes/connections
    that emulator will be our next hop for this destination
"""

def append_own_send_info(payload, self_ip, self_port):
    return payload + "|" + str(self_ip) + ":" + str(self_port)

def decode_lsv_route_trace(packet_inner_data):
    link_state_vector = []
    lsv = packet_inner_data.decode('utf-8')
    ip_port_pairs = lsv.split("|")
    for each_pair in ip_port_pairs:
        dest_ip_addr, dest_port = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port)])
    return link_state_vector
