import argparse
import logging
import socket
import struct
from queue import PriorityQueue, Empty

if __name__ == "__main__":
    # 1. Parse arguments
    parser = argparse.ArgumentParser(description="Emulates network for UDP")
    parser.add_argument("-p", "--port", dest="port", type=int, required=True, help="Port on which the emulator runs")
    parser.add_argument("-q", "--queue-size", dest="queue_size", type=int, required=True, help="Size of the message queue on the current network emulator")
    parser.add_argument("-f", "--filename", dest="forwarding_filename", type=str, required=True, help="File containing information about the static forwarding table")
    parser.add_argument("-l", "--logfile", dest="logfilename", type=str, required=True, help="Name of the log file")

    args = parser.parse_args()

    # 2. Setup logging
    LOG = logging.basicConfig(
            filename=args.logfilename,
            level=logging.ERROR,
            format="%(asctime)s - %(levelname)s - %(message)s",
            datefmt='%Y-%m-%0d %H:%M:%0S'
            )
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
                    fwd_table.append(tuple([dest_host_name, int(dest_port), next_hop_host_name, int(next_hop_port), int(delay), int(loss_prob)]))
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
    sock.bind(('0.0.0.0', args.port))
    sock.setblocking(False)
    # Run the logic in loop
    while True:
        data, addr = sock.recvfrom(1024)
        # Unpack the information from the received socket datagram
        if data:
            # process the received data
            pass
        else:
            # Pop the first item from the priority queue
            object = None
            try:
                object = priority_1_queue.get(block=False, timeout=0)
            except Empty as em:
                object = None
                pass
            if object is None:
                try:
                    object = priority_2_queue.get(block=False, timeout=0)
                except Empty as em:
                    object = None
                    pass
            if object is None:
                try:
                    object = priority_3_queue.get(block=False, timeout=0)
                except Empty as em:
                    object = None
                    pass
            if object is None:
                continue
            else:
                # Send the packet over the network
                pass
            


