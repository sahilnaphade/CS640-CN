import argparse
import logging
import socket
from queue import PriorityQueue, Empty
import random
from time import time
from io import BlockingIOError
from utils import *
from threading import Event, Thread

packet_is_being_delayed = False

def delay_and_send(packet, delay, next_hop_IP, next_hop_port, seq_no, source_ip, source_port, dest_ip, dest_port, loss_prob):
    global packet_is_being_delayed
    try:
        packet_is_being_delayed = True
        priority, src_ip_addr, src_port, dst_ip_addr, dst_port, length, packet_type, sequence_number, inner_length, data = outer_payload_decapsulate(packet)
        delay_event = Event()
        delay_event.wait(delay)
        if next_hop_IP is None:
            LOG.error(f"ROUTE DROP - Packet seq:{seq_no}, Priority:{priority}, packet_type:{packet_type}, length:{inner_length} | Source:{str(source_ip)}:{source_port} | Destination:{str(dest_ip)}:{dest_port} | Reason: Forwarding entry not found")
            return
        if packet_type in ['D', 'A']:
            # print(loss_prob)
            if random.random() < float(loss_prob):
                LOG.error(f"SEND  DROP - Packet seq:{seq_no}, Priority:{priority}, packet_type:{packet_type}, length:{inner_length} | Source:{str(source_ip)}:{source_port} | Destination:{str(dest_ip)}:{dest_port} | Reason: Loss event occurred")
                return
        LOG.info(f"Sent the packet @ {seq_no} at time: {time()}")
        send_packet(packet, next_hop_IP, next_hop_port, log_handler=LOG)
        return
    except Exception as ex:
        raise ex
    finally:
        packet_is_being_delayed = False

def get_routing(packet_dest_ip, packet_dest_port, forwarding_table):
    for entry in forwarding_table:
        if entry[0] == packet_dest_ip and entry[1] == packet_dest_port:
            next_hop_host_name = entry[2]
            next_hop_port = int(entry[3])
            delay = float(entry[4])
            loss_prob = float(entry[5])
            return next_hop_host_name, next_hop_port, delay, loss_prob
    return None, None, None, None


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
        level=logging.ERROR,
        format="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
        # datefmt='%H:%M:%S',
        datefmt='%H:%M:%S'
    )
    LOG = logging.getLogger(__name__)
    # LOG.exception("Starting!")

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
                    fwd_table.append(tuple([dest_host_ip, int(dest_port), next_hop_ip, int(next_hop_port), float(int(delay)/1000), float(int(loss_prob)/100)]))
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
        packet = None
        data = addr = None
        try:
            # print(type(sock))
            data, addr = sock.recvfrom(1024)
        except BlockingIOError as bie:
            pass
        # If we receive a packet -> unpack the information from the received socket datagram
        if data:
            priority, source_ip, source_port, dest_ip, dest_port, length, packet_type, seq_no, inner_length, payload = outer_payload_decapsulate(data)
            # print(f"priority: {priority}, src: {source_ip}@{source_port} -> dest: {dest_ip}@{dest_port}, length: {inner_length}")
            queue_full = False
            priority = str(priority)
            if priority == '1':
                # print("Adding the packet to queue 1")
                if priority_1_queue.full():
                    queue_full = True
                    if packet_type == 'E':
                        pass
                    else:
                        LOG.error(f"QUEUE DROP - Packet seq:{seq_no}, Priority:{priority}, packet_type:{packet_type}, length:{inner_length} | Source: {str(source_ip)}:{source_port} | Destination: {str(dest_ip)}:{dest_port} | Reason: Full queue")
                        continue
                LOG.info(f"Adding Packet seq: {seq_no} Priority: {priority} from src: {str(source_ip)} dest: {str(dest_ip)} packet_type: {packet_type} in QUEUE 1")
                priority_1_queue.put(data)
            elif priority == '2':
                # print("Adding the packet to queue 2")
                if priority_2_queue.full():
                    queue_full = True
                    if packet_type == 'E':
                        pass
                    else:
                        LOG.error(f"QUEUE DROP - Packet seq:{seq_no}, Priority:{priority}, packet_type:{packet_type}, length:{inner_length} | Source: {str(source_ip)}:{source_port} | Destination: {str(dest_ip)}:{dest_port} | Reason: Full queue")
                        continue
                    LOG.info(f"Adding Packet seq: {seq_no} Priority: {priority} from src: {str(source_ip)} dest: {str(dest_ip)} packet_type: {packet_type} in QUEUE 2")
                priority_2_queue.put(data)
            else:
                # print("Adding the packet to queue 3")
                if priority_3_queue.full():
                    queue_full = True
                    if packet_type == 'E':
                        pass
                    else:
                        LOG.error(f"QUEUE DROP - Packet seq:{seq_no}, Priority:{priority}, packet_type:{packet_type}, length:{inner_length} | Source: {str(source_ip)}:{source_port} | Destination: {str(dest_ip)}:{dest_port} | Reason: Full queue")
                        continue
                LOG.info(f"Adding Packet seq: {seq_no} Priority: {priority} from src: {str(source_ip)} dest: {str(dest_ip)} packet_type: {packet_type} in QUEUE 3")
                priority_3_queue.put(data)
            if queue_full and packet_type == 'E':
                next_hop_host_name, next_hop_port, delay, loss_prob  = get_routing(dest_ip, dest_port, fwd_table)
                send_packet(packet, next_hop_host_name, next_hop_port)
            pass
        # The packets are received. Now check if any packet is being delayed
        # If not, try to transmit a new packet
        if not packet_is_being_delayed:
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
                priority, source_ip, source_port, dest_ip, dest_port, length, packet_type, seq_no, inner_length, data = outer_payload_decapsulate(packet)
                next_hop_host_name = next_hop_port = loss_prob = delay = None
                next_hop_host_name, next_hop_port, delay, loss_prob = get_routing(dest_ip, dest_port, fwd_table)
                # LOG.info(f"Adding a packet @ {seq_no} at time: {time()}, delay is {delay}")
                t1 = Thread(target=delay_and_send, args=[packet, delay, next_hop_host_name, next_hop_port, seq_no, source_ip, source_port, dest_ip, dest_port, loss_prob])
                t1.start()
                continue
        else:
            continue

