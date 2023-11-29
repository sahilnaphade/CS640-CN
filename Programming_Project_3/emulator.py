import argparse
import logging
import socket
from queue import PriorityQueue, Empty
import random
from time import time
from io import BlockingIOError
from utils import *
from threading import Event, Thread

# packet_is_being_delayed = False
PACKET_TYPE_HELLO = "H"
PACKET_TYPE_LINK_STATE = "L"
PACKET_TYPE_ROUTE_TRACE = "R"
NO_MESSAGE_TOLERANCE = 3 # Total count of deltas before removing the entry
HELLO_MESSAGE_DELTA = 500 # in milliseconds (TBD)

FWD_TABLE_DEST_IDX = 0
FWD_TABLE_NEXT_HOP_IDX = 1
FWD_TABLE_COST_IDX = 2
FWD_TABLE_VALID_IDX = 3

helloTimestamps = {}
largestSeqNoPerNode = {}
myLastHello = None # Timestamp of last hello message
myLSN = 1

def build_forwarding_table(route_topology):
    pass

def send_hello_message(src_ip, src_port, dest_ip, dest_port):
    global myLSN
    send_sock = None
    inner_pack = inner_payload_encapsulate(PACKET_TYPE_HELLO, myLSN, "", 0)
    final_pack = outer_payload_encapsulate(src_ip, src_port, dest_ip, dest_port, inner_pack)
    try:
        send_sock = socket.socket(socket.AF_INET, socket.AF_INET)
        send_sock.sendto(final_pack, (dest_ip, dest_port))
    except Exception as ex:
        pass
    finally:
        if send_sock is not None:
            send_sock.close()
        myLSN += 1
    pass

def send_link_state_message():
    pass

def forward_packet():
    pass

if __name__ == "__main__":
    # 1. Parse arguments
    parser = argparse.ArgumentParser(description="Emulates network for UDP")
    parser.add_argument("-p", "--port", dest="port", type=int, required=True, help="Port on which the emulator runs")
    # parser.add_argument("-q", "--queue-size", dest="queue_size", type=int, required=True, help="Size of the message queue on the current network emulator")
    parser.add_argument("-f", "--filename", dest="topology_file", type=str, required=True, help="File containing information about the static forwarding table")
    # parser.add_argument("-l", "--logfile", dest="logfilename", type=str, required=True, help="Name of the log file")

    args = parser.parse_args()

    # 2. Setup logging
    logging.basicConfig(
        filename=args.logfilename,
        filemode="w",
        level=logging.ERROR,
        format="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
        # datefmt='%H:%M:%S',
        datefmt='%H:%M:%S'
    )
    LOG = logging.getLogger(__name__)
    # LOG.exception("Starting!")
    # 3. Read the topology and get the immediately adjacent nodes of current node
    self_name = socket.gethostname()
    self_ip = socket.gethostbyname(self_name)    
    my_adjacent_nodes = []
    with open(args.topology_file, "r") as topo_file:
        file_data = topo_file.readlines()
        for each_adjacent_topology in file_data:
            if each_adjacent_topology != '\n':
                # Check if we are reading the adjacent nodes for the current node
                current_topology = each_adjacent_topology.split(" ")
                source_ip, source_port = current_topology[0].split(',')
                if source_ip == self_name or source_ip == self_ip:
                    if source_port == int(args.port):
                        # We are reading the topology for the current node -- add the nodes to the in-mem cache
                        my_adjacent_nodes.append(tuple(current_topology[index].split(",")) for index in range(1, len(current_topology)))
    
    # 3. Initialize forwarding table (list of tuples)
    # Any tuple: ((dest_ip, dest_port), (next_hop_ip, next_hop_port), cost, isvalid)
    fwd_table = []

    read_sock = None
    try:
        read_sock = socket.socket(socket.AF_INET, # Internet
                            socket.SOCK_DGRAM) # UDP
    except Exception as ex:
        raise ex
    read_sock.setblocking(False)
    read_sock.bind(('0.0.0.0', args.port))
    # Run the logic in loop
    while True:
        packet = None
        data = addr = None
        try:
            # print(type(read_sock))
            data, addr = read_sock.recvfrom(1024)
        except BlockingIOError as bie:
            pass
        # If we receive a packet -> unpack the information from the received socket datagram
        if data:
            # TODO may need to change the implementation of the decapsulate based on the requirement
            priority, src_ip, src_port, dst_ip, dst_port, length, packet_type, seq_no, inner_len, inner_data = outer_payload_decapsulate(data)
            # Check what is the type of the message received
            source = tuple(src_ip, src_port)
            # Case A: It is a Data/End/Request packet -- forward to next hop
            if packet_type in ['D', 'E', 'R']:
                next_hop_found = False
                for each_fwd_entry in fwd_table:
                    # If the destination entry exists and the route is valid, fwd the packet to their next hop
                    if each_fwd_entry[FWD_TABLE_DEST_IDX] == tuple(dst_ip, dst_port) and\
                        each_fwd_entry[FWD_TABLE_VALID_IDX] == True:
                            next_hop_found = True
                            send_packet(data, each_fwd_entry[FWD_TABLE_NEXT_HOP_IDX][0], each_fwd_entry[FWD_TABLE_NEXT_HOP_IDX][1])
                            break
                if not next_hop_found:
                    LOG.error(f"Destination {dst_ip}:{dst_port} not found in fwd table."
                              " Dropping the packet.")
                    pass
            # Case B: If it is a HELLO packet from neighbour -> update the timestamp of Hello
            # TODO Should check if it is a neighbour or not?
            # TODO Verify from book if anything else is expected here
            elif packet_type == PACKET_TYPE_HELLO:
                helloTimestamps[source] = time()
                # if (node, port) not in fwd_table (The node was unavailable till now)
                # Set the route to itself and set cost as 1 for the neighbour
                if not any(entry[FWD_TABLE_DEST_IDX] == source for entry in fwd_table):
                    fwd_table.append(tuple(source, source, 1, True))
                    # Send LinkStateMessage to all neighbors
                    send_link_state_message() # TODO
            # Case C: If a Link State message
            elif packet_type == PACKET_TYPE_LINK_STATE:
                #   Check the LSN and check if new. Discard if not            
                if largestSeqNoPerNode.get(source, 0) < seq_no:
                    # The sequence number is valid
                    largestSeqNoPerNode[source] = seq_no
                    #  TODO  Topology change == update the route topology and fwd_table
                    decode_link_state_data(inner_data)
                    #   Call forwardpacket to flood to neighbours
                    for each_neighbour in my_adjacent_nodes:
                        forward_packet(data, each_neighbour[0], each_neighbour[1]) #TODO
                else:
                    pass
            # Case 4: It is routetrace packet -> TODO
            pass
        # 3. Send the HelloMessage if timedelta has passed
        if time() - myLastHello >= HELLO_MESSAGE_DELTA:
            for adj_node in my_adjacent_nodes:
                send_hello_message(self_ip, args.port, adj_node[0], adj_node[1])
            myLastHello = time()
        # 4. Check the neighbors and update the fwd table as required
        for neighbour, lastHelloTS in helloTimestamps.items():
            if time() - lastHelloTS > NO_MESSAGE_TOLERANCE*HELLO_MESSAGE_DELTA:
                # remove all the entries from the table for which this neighbour was the next hop
                # Rebuild (?) the fwd table
                for fwd_entry in fwd_table:
                    if (fwd_entry[FWD_TABLE_NEXT_HOP_IDX] == neighbour):
                        fwd_entry[FWD_TABLE_VALID_IDX] = False
                pass
        # 5. Send the newest LinkStateMessage to all neighbors if time has passed
        send_link_state_message()
        continue
