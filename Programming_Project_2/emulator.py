import argparse
import logging
import socket
import struct
from queue import PriorityQueue, Empty
import random
import ipaddress
from io import BlockingIOError

def send_packets(packet, fwd_table, LOG):
    # Get the forwarding host and port from the packet
    # host = get_from_table_and_packet TODO

    host_name = host_port = None
    next_hop_host_name = next_hop_port = loss_prob = None
    outer_header = packet[0:17]
    outer_header_up = struct.unpack("cIhIhI", outer_header)
    dest_ip_int = outer_header_up[3]
    dest_port = outer_header_up[4]
    dst_ip = str(ipaddress.ip_address(dest_ip_int))
    dst_port = int(dest_port)
    for entry in fwd_table:
        if entry[0] == dst_ip and entry[1] == dst_port:
            next_hop_host_name = entry[2]
            next_hop_port = entry[3]
            loss_prob = entry[5]
            break
    packet_type = packet[17:18].decode('utf-8')
    # Drop only non-END packets
    if packet_type != "E":
        prob = random.random()
        if prob < loss_prob:
            # LOG.error(f"SEND  DROP Packet seq: {packet_seq_no} Priority: {priority} from src: {str(src_ip)} dest: {str(dst_ip)} dropped due to full queue")
            return
    if next_hop_host_name is None:
        LOG.exception(f"ROUTE DROP The host {dst_ip} is not in the forwarding table. Dropping the packet".format(next_hop_host_name))
        return
    # We had the full packet (including the header) in the queue - send it over the network
    # TODO Delay the packet
    send_socket = None
    try:
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        send_socket.sendto((packet), (next_hop_host_name, next_hop_port))
    except Exception as ex:
        LOG.exception(ex)
        raise ex
    finally:
        if send_socket is not None:
            send_socket.close()


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
        level=logging.ERROR,
        format="%(asctime)s - %(levelname)s - %(message)s",
        datefmt='%Y-%m-%0d %H:%M:%0S'
    )
    LOG = logging.Logger(__name__, logging.DEBUG)
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
    print(fwd_table)

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
        # Unpack the information from the received socket datagram
        if data:
            outer_header = data[0:17]
            outer_header_up = struct.unpack("cIhIhI", outer_header)
            priority, src_ip_int, src_port, dest_ip_int, dest_port, length = outer_header_up
            src_ip = ipaddress.ip_address(src_ip_int)
            dst_ip = ipaddress.ip_address(dest_ip_int)
            print(f"priority: {priority}, src: {src_ip}@{src_port} dest: {dst_ip}@{dest_port}, length: {length}")

            payload_for_outer = data[17:] # payload_for_outer = inner_header + inner_payload
            payload_for_outer_up = struct.unpack('II', payload_for_outer[1:9])
            packet_seq_no = socket.ntohl(outer_header_up[0])
            
            priority = int(priority)
            if priority == 1:
                if priority_1_queue.full():
                    LOG.error(f"QUEUE DROP Packet seq: {packet_seq_no} Priority: {priority} from src: {str(src_ip)} dest: {str(dst_ip)} dropped due to full queue")
                    continue
                priority_1_queue.put(data)
            elif priority == 2:
                if priority_2_queue.full():
                    LOG.error(f"QUEUE DROP Packet seq: {packet_seq_no} Priority: {priority} from src: {str(src_ip)} dest: {str(dst_ip)} dropped due to full queue")
                    continue
                priority_2_queue.put(data)
            else:
                if priority_3_queue.full():
                    LOG.error(f"QUEUE DROP Packet seq: {packet_seq_no} Priority: {priority} from src: {str(src_ip)} dest: {str(dst_ip)} dropped due to full queue")
                    continue
                priority_3_queue.put(data)
            pass
        else:
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
                LOG.info("No messages in any priority queue")
                continue
            else:
                # Route and Send the packet over the network, after making sure of the packet dropping
                send_packets(packet, fwd_table, LOG)
                pass
