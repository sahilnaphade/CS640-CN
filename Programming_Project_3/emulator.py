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
HELLO_MESSAGE = 1
LINK_STATE_MESSAGE = 2
NO_MESSAGE_TOLERANCE = 3 # Total count of deltas before removing the entry
HELLO_MESSAGE_DELTA = 500 # in milliseconds (TBD)


helloTimestamps = {}
largestSeqNoPerNode = {}
myLastHello = None # Timestamp of last hello message
myLSN = 1

def build_forwarding_table(route_topology):
    pass

def send_hello_message():
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
    parser.add_argument("-f", "--filename", dest="forwarding_filename", type=str, required=True, help="File containing information about the static forwarding table")
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
    with open("topology.txt", "r") as topology_file:
        file_data = topology_file.readlines()
        for each_adjacent_topology in file_data:
            if each_adjacent_topology != '\n':
                # Check if we are reading the adjacent nodes for the current node
                current_topology = each_adjacent_topology.split(" ")
                source_ip, source_port = current_topology[0].split(',')
                if source_ip == self_name or source_ip == self_ip:
                    if source_port == int(args.port):
                        # We are reading the topology for the current node -- add the nodes to the in-mem cache
                        my_adjacent_nodes.append(tuple(current_topology[index].split(",")) for index in range(1, len(current_topology)))
    
    # 3. Initialize forwarding table
    # (dest_ip, dest_port, next_hop_ip, next_hop_port)
    fwd_table = []

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, # Internet
                            socket.SOCK_DGRAM) # UDP
    except Exception as ex:
        raise ex
    sock.setblocking(False)
    sock.bind(('0.0.0.0', args.port))
    # Run the logic in loop
    while True:
        packet = None
        data = addr = None
        try:
            # print(type(sock))
            data, addr = sock.recvfrom(1024)
        except BlockingIOError as bie:
            pass
        # If we receive a packet -> unpack the information from the received socket datagram
        if data:
            # TODO may need to change the implementation of the decapsulate based on the requirement
            priority, src_ip, src_port, dst_ip, dst_port, length, packet_type, seq_no, inner_len, data = outer_payload_decapsulate(data)
            # Check what is the type of the message received
            # Case 1: It is a helloMessage
            # helloTimeStamp[(node, port)] = time.time()
            # if (node, port) not in fwd_table,
            #   Update the route topology and fwd table
            #   Send LinkStateMessage to all neighbors
            #   TODO Verify from book what is the expected thing here
            # Case 2: It is a LinkStateMessage
            #   Check the LSN and check if new. Discard if not
            #   Topology change == update the route topology and fwd_table
            #   Call forwardpacket to flood to neighbours
            # Case 3: It is a Data/End/Request packet -- forward to next hop
            if packet_type in ['D', 'E', 'R']:
                next_hop_found = False
                for each_fwd_entry in fwd_table:
                    if each_fwd_entry[0] == dst_ip and each_fwd_entry[1] == dst_port:
                        next_hop_found = True
                        send_packet(data, each_fwd_entry[2], each_fwd_entry[3])
                if not next_hop_found:
                    LOG.error(f"Destination {dst_ip}:{dst_port} not found in fwd table. Dropping the packet.")
            # Case 4: It is routetrace packet -> TODO
            pass
        # 3. Send the HelloMessage if timedelta has passed
        if time() - myLastHello >= HELLO_MESSAGE_DELTA:
            send_hello_message()
            myLastHello = time()
        # 4. Check the neighbors and update the fwd table as required
        for neighbour, lastHelloTS in helloTimestamps.items():
            if time() - lastHelloTS > NO_MESSAGE_TOLERANCE*HELLO_MESSAGE_DELTA:
                # remove the neighbour from the fwd table
                # Rebuild (?) the fwd table
                pass
        # 5. Send the newest LinkStateMessage to all neighbors if time has passed
        send_link_state_message()
        continue
