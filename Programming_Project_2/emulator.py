import argparse
import logging
import socket
import struct
from queue import PriorityQueue, Empty
import random
import ipaddress
from io import BlockingIOError
from utils import *

if __name__ == "__main__":
    # 1. Parse arguments
    parser = argparse.ArgumentParser(description="Emulates network for UDP")
    parser.add_argument("-p", "--port", dest="port", type=int, required=True, help="Port on which the emulator runs")
    parser.add_argument("-q", "--queue-size", dest="queue_size", type=int, required=True, help="Size of the message queue on the current network emulator")
    parser.add_argument("-f", "--filename", dest="forwarding_filename", type=str, required=True, help="File containing information about the static forwarding table")
    parser.add_argument("-l", "--logfile", dest="logfilename", type=str, required=True, help="Name of the log file")

    args = parser.parse_args()

    # 2. Setup logging
    logging.basicConfig(
        filename=args.logfilename,
        filemode="w",
        level=logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
        # datefmt='%H:%M:%S',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    LOG = logging.getLogger(__name__)
    LOG.exception("Starting!")

    # 3. Read forwarding table and initialize priority queues
    fwd_table = []
    with open(args.forwarding_filename, "r") as fwd_table_file:
        full_table = fwd_table_file.readlines()
        self_ip = socket.gethostbyname(socket.gethostname())
        self_name = socket.gethostname()
        for each_emulator in full_table:
            if each_emulator != "\n":
                # For each line in the forwarding table, only get the lines which are corresponding to self name/IP and port
                emulator_name, emulator_port, dest_host_name, dest_port, next_hop_host_name, next_hop_port, delay, loss_prob = each_emulator.split(" ")
                if (emulator_name == self_ip or emulator_name == self_name) and int(emulator_port) == args.port:
                    dest_host_ip = socket.gethostbyname(dest_host_name)
                    next_hop_ip = socket.gethostbyname(next_hop_host_name)
                    fwd_table.append(tuple([dest_host_ip, int(dest_port), next_hop_ip, int(next_hop_port), int(delay), int(loss_prob)/100]))
    LOG.info(fwd_table)

    priority_1_queue = PriorityQueue(maxsize=args.queue_size)
    priority_2_queue = PriorityQueue(maxsize=args.queue_size)
    priority_3_queue = PriorityQueue(maxsize=args.queue_size)

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
        data = addr = None
        try:
            # print(type(sock))
            data, addr = sock.recvfrom(1024)
        except BlockingIOError as bie:
            pass
        # If we receive a packet -> unpack the information from the received socket datagram
        if data:
            priority, source_ip, source_port, dest_ip, dest_port, length, packet_type, seq_no, payload = outer_payload_decapsulate(data)
            print(f"priority: {priority}, src: {source_ip}@{source_port} -> dest: {dest_ip}@{dest_port}, length: {length}")
            
            priority = int(priority)
            if priority == 1:
                if priority_1_queue.full():
                    LOG.error(f"QUEUE DROP - Packet seq: {seq_no} Priority: {priority} from src: {str(source_ip)} dest: {str(dest_ip)} dropped due to full queue")
                    continue
                priority_1_queue.put(data)
            elif priority == 2:
                if priority_2_queue.full():
                    LOG.error(f"QUEUE DROP - Packet seq: {seq_no} Priority: {priority} from src: {str(source_ip)} dest: {str(dest_ip)} dropped due to full queue")
                    continue
                priority_2_queue.put(data)
            else:
                if priority_3_queue.full():
                    LOG.error(f"QUEUE DROP - Packet seq: {seq_no} Priority: {priority} from src: {str(source_ip)} dest: {str(dest_ip)} dropped due to full queue")
                    continue
                priority_3_queue.put(data)
            pass
        # The packets are received. Now try to transmit if any
        # Pop the first item from the priority queue
        packet = None
        try:
            packet = priority_1_queue.get(block=False, timeout=0)
        except Empty as em:
            LOG.debug("No message found")
            packet = None
            pass
        # If there are no 1 priority elements, get priority 2 elements
        if packet is None:
            try:
                packet = priority_2_queue.get(block=False, timeout=0)
            except Empty as em:
                packet = None
                pass
        # If there are no 2 priority elements, get priority 3 elements
        if packet is None:
            try:
                packet = priority_3_queue.get(block=False, timeout=0)
            except Empty as em:
                packet = None
                pass
        if packet is None:
            LOG.debug("No messages in any priority queue")
            continue
        else:
            priority, source_ip, source_port, dest_ip, dest_port, length, packet_type, seq_no, data = outer_payload_decapsulate(packet)
            for entry in fwd_table:
                if entry[0] == dest_ip and entry[1] == dest_port:
                    next_hop_host_name = entry[2]
                    next_hop_port = int(entry[3])
                    loss_prob = float(entry[5])
                    break
            if next_hop_host_name is None:
                LOG.error(f"ROUTE DROP - Destination Host '{dest_ip}@{dest_port}' is not in the forwarding table. Dropping the packet")
                continue
            if packet_type != 'E':
                print(loss_prob)
                if random.random() < float(loss_prob):
                    LOG.error(f"SEND  DROP - source: {source_ip}@{source_port} seqno: {seq_no} destination: {dest_ip}@{dest_port}")
                    continue
            send_packet(packet, next_hop_host_name, next_hop_port, log_handler=LOG)
            pass
