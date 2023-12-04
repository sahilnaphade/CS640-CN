import argparse
import logging
import socket
from queue import PriorityQueue, Empty
import random
from time import time
# from prettytable import PrettyTable
from io import BlockingIOError
from utils import *
from threading import Event, Thread

DEBUG_PRINT = False

# packet_is_being_delayed = False
NO_MESSAGE_TOLERANCE = 3 # Total count of misses before removing the entry
HELLO_MESSAGE_DELTA = 300 # in milliseconds (TBD)
LINK_STATE_MSG_TIMEOUT = 300

helloTimestamps = {}
largestSeqNoPerNode = {}
myLastHello = 0 # Timestamp of last hello message
myLastLSM = 0
myLSN = 1

def print_fwd_table(fwd_table):
    print(['   Dest IP  ', 'Dest Port', 'Next Hop IP', "Next hop port", "Cost"])
    for entry in fwd_table:
        destination = entry[FWD_TABLE_DEST_IDX]
        next_hop = entry[FWD_TABLE_NEXT_HOP_IDX]
        cost = entry[FWD_TABLE_COST_IDX]
        if next_hop == None:
            print([destination[0], destination[1], "None", "None", cost])
        else:
            print([destination[0], destination[1], next_hop[0], next_hop[1], cost])
    print("\n\n")

def send_hello_message(src_ip, src_port, dest_ip, dest_port):
    global myLSN, myLastHello
    send_sock = None
    inner_pack = inner_payload_encapsulate(PACKET_TYPE_HELLO, myLSN, "", 0)
    final_pack = outer_payload_encapsulate(src_ip, src_port, dest_ip, dest_port, inner_pack)
    try:
        send_sock = socket.socket(socket.AF_INET, socket.AF_INET)
        send_sock.sendto(final_pack, (dest_ip, dest_port))
        myLastHello = round(time() * 1000)
        # if DEBUG_PRINT:
            # print(f"Sent hello to {dest_ip}:{dest_port} at time {myLastHello}")
    except Exception as ex:
        pass
    finally:
        if send_sock is not None:
            send_sock.close()
        myLSN += 1
    pass

def send_link_state_message(my_adj_nodes, fwd_table,TTL,self_ip, port):  #TODO : check if we are incrementing TTL when calling this function amid topology change
    global myLastLSM
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
        payload = generate_link_state_vector(fwd_table) # Will encode the full forwarding table until then as payload
        print(payload)
        inner_payload = inner_payload_encapsulate(PACKET_TYPE_LINK_STATE, 0, payload, TTL) # payload length in the inner header is TTL
        #Iterate through all the adjacent nodes and send the forwarding table
        for node in my_adj_nodes:
            packet = outer_payload_encapsulate(self_ip,port,node[0],node[1],inner_payload)
            sock.sendto(packet,(node[0],node[1]))
        myLastLSM = round(time() * 1000)
        if DEBUG_PRINT:
            print(f"Sending the LinkStateMessage to the neighbours at time {myLastLSM}")
    except Exception as ex:
        raise ex
    finally:
        if sock is not None:
            sock.close()

def forward_packet(data, my_adjacent_nodes,fwd_table,self_ip,self_port):
    socket = None
    priority,src_ip,src_port,dest_ip,dest_port,length,packet_type,seq_no,current_TTL,payload = outer_payload_decapsulate(data)
    try:
        socket = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
        if packet_type == PACKET_TYPE_LINK_STATE:
            if not current_TTL:
                current_TTL -= 1
                inner_payload = inner_payload_encapsulate('L',seq_no,payload,current_TTL)
                for node in my_adjacent_nodes:
                    packet = outer_payload_encapsulate(src_ip,src_port,node[0],node[1],inner_payload)
                    socket.sendto(packet,(node[0],node[1]))
        elif packet_type == PACKET_TYPE_ROUTE_TRACE:
            # Check if current_TTL is zero, if yes then need to send the route trace reply packet to the route trace applicaiton
            # with src ip and port of its own and dest ip and port of the route trace packet
            if current_TTL == 0:
                decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
                current_TTL = len(decoded_payload) - 1 # Total number of hops, as we append all the IP:port to the payload
                next_hop_for_packet = decoded_payload[-1]
                inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
                packet = outer_payload_encapsulate(self_ip,self_port,decoded_payload[0][0],decoded_payload[0][1],inner_payload)
                
                # send reply packet back to the route trace applicaiton.
                socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]) )
                if DEBUG_PRINT:
                    print(f"The TTL for the route trace is 0. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the LSV is {' <- '.join(decoded_payload)}")
                
                #TODO : Need to verify packet format consistency with the project requirements : source port, ip
            else :
                for entry in fwd_table:
                    if entry[FWD_TABLE_DEST_IDX] == dest_ip: # Check the nexthop for the destination in the forwarding table
                        current_TTL -= 1  # decrement the TTL and create new packet and send to the next hop.
                        # Update own info to the payload (for the next hop while returning)
                        # This will follow the same format as standard package, except COST
                        payload = append_own_send_info(payload, self_ip, self_port)

                        inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE,0,payload,TTL)
                        
                        packet = outer_payload_encapsulate(src_ip,src_port,dest_ip,dest_port,inner_payload)
                        socket.sendto(packet,(entry[FWD_TABLE_NEXT_HOP_IDX][0],entry[FWD_TABLE_NEXT_HOP_IDX][1]))
                        if DEBUG_PRINT:
                            print(f"The TTL for the route trace is {current_TTL}. Forwarding to the next HOP @ {entry[FWD_TABLE_NEXT_HOP_IDX][0]}:{entry[FWD_TABLE_NEXT_HOP_IDX][1]}, the payload is {payload}")
                        break
        elif packet_type == PACKET_TYPE_ROUTE_TRACE_REPLY:
            # If the packet is simply going back, get the last TTLth record in the payload, that will be our next hop
            # TODO check
            decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
            current_TTL = current_TTL - 1 # Total number of hops, as we append all the IP:port to the payload
            next_hop_for_packet = decoded_payload[(-1)*(current_TTL)]
            inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
            packet = outer_payload_encapsulate(self_ip,self_port,decoded_payload[0][0],decoded_payload[0][1],inner_payload)
            if DEBUG_PRINT:
                print(f"Reply packet. Forwarding towards sender. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the payload is {payload}")
            # send reply packet back to the route trace applicaiton.
            socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]) )
    except Exception as ex:
        print(ex)
    finally:
        if socket is not None:
            socket.close()
        
                
        
            
            
            
        
    

# Souce of LSV will always be the immediate adjacent == cost will increment by 1
def update_fwd_table(fwd_table, received_lsv, source_of_lsv):
    next_hop_lsv_destinations = [entry[FWD_TABLE_DEST_IDX] for entry in fwd_table if entry[FWD_TABLE_NEXT_HOP_IDX] == source_of_lsv]
    receieved_lsv_dest = [tuple([lsv_entry[0], lsv_entry[1]]) for lsv_entry in received_lsv]

    print("Current FWD table is {}".format(fwd_table))
    topo_updated = False
    print("next_hop_lsv_destinations {}: {}".format(len(next_hop_lsv_destinations), next_hop_lsv_destinations))
    print("receieved_lsv_dest {}: {}".format(len(receieved_lsv_dest), receieved_lsv_dest))
    # If The received LSV has some removed paths -- remove that entry from fwd_table
    # TODO: Check actual values, not only length
    if len(next_hop_lsv_destinations) != len(receieved_lsv_dest):
        for each_dest in next_hop_lsv_destinations: # Fwd table
            if each_dest not in receieved_lsv_dest and each_dest != source_of_lsv:
                entry_to_delete = next((fwd_en for fwd_en in fwd_table if\
                                        fwd_en[FWD_TABLE_DEST_IDX] == each_dest))
                print("Deleting the entry {} from the FWD table".format(entry_to_delete))
                fwd_table.remove(entry_to_delete)
                topo_updated = True
    print("Now checking if a node needs to be added")
    # Add new entries if remaining 
    for each_lsv_entry in received_lsv:
        dest_ip_port = tuple([each_lsv_entry[0], each_lsv_entry[1]])
        dest_cost = each_lsv_entry[2]
        for each_fwd_entry in fwd_table:
            # If we find the entry in the LSDB
            if each_fwd_entry[FWD_TABLE_DEST_IDX] == dest_ip_port:
                current_cost = float('inf') if each_fwd_entry[FWD_TABLE_COST_IDX] is None else each_fwd_entry[FWD_TABLE_COST_IDX]
                if dest_cost is None:
                    # TODO Have to update the entry in the Forwarding table
                    pass 
                incoming_cost = dest_cost + 1 # As the LSV is from the immediate neighbour
                if each_fwd_entry[FWD_TABLE_NEXT_HOP_IDX] == source_of_lsv:
                    if incoming_cost != current_cost:
                        each_fwd_entry[FWD_TABLE_COST_IDX] = incoming_cost
                        if DEBUG_PRINT:
                            print("Incoming cost for the destination {} is {}, "
                                "existing cost is {}. Updated the entry."
                                .format(dest_ip_port, incoming_cost, current_cost))
                        topo_updated = True
                else:
                    if incoming_cost < current_cost:
                        print("Updating the incoming cost to {}".format(incoming_cost))
                        each_fwd_entry[FWD_TABLE_NEXT_HOP_IDX] = source_of_lsv
                        each_fwd_entry[FWD_TABLE_COST_IDX] = incoming_cost
            else:
                already_have_entry = any(x for x in fwd_table if x[FWD_TABLE_DEST_IDX] == dest_ip_port)
                if already_have_entry:
                    break
                print("Entry not found in the FWD Table. cost for the destination {} is {}, "
                    "Updating the entry."
                    .format(dest_ip_port, dest_cost +1))
                fwd_table.append([dest_ip_port, source_of_lsv, dest_cost+1])
                break
    # print("Updated FWD table is now {}".format(fwd_table))
    print_fwd_table(fwd_table)
    return topo_updated


if __name__ == "__main__":
    # 1. Parse arguments
    parser = argparse.ArgumentParser(description="Emulates network for UDP")
    parser.add_argument("-p", "--port", dest="port", type=int, required=True, help="Port on which the emulator runs")
    # parser.add_argument("-q", "--queue-size", dest="queue_size", type=int, required=True, help="Size of the message queue on the current network emulator")
    parser.add_argument("-f", "--filename", dest="topology_file", type=str, required=True, help="File containing information about the static forwarding table")
    # parser.add_argument("-l", "--logfile", dest="logfilename", type=str, required=True, help="Name of the log file")

    args = parser.parse_args()

    # # 2. Setup logging
    # logging.basicConfig(
    #     filename=args.logfilename,
    #     filemode="w",
    #     level=logging.ERROR,
    #     format="%(asctime)s.%(msecs)03d - %(levelname)s - %(message)s",
    #     # datefmt='%H:%M:%S',
    #     datefmt='%H:%M:%S'
    # )
    # LOG = logging.getLogger(__name__)
    # LOG.exception("Starting!")
    # 3. Read the topology and get the immediately adjacent nodes of current node
    self_name = socket.gethostname()
    self_ip = socket.gethostbyname(self_name)    
    my_adjacent_nodes = []
    self_host = tuple([self_ip, int(args.port)])
    full_network_topology = set() # List of all nodes in the current network
    TTL = 0

    with open(args.topology_file, "r") as topo_file:
        # file_data = topo_file.readlines()
        for each_adjacent_topology in topo_file:
            each_adjacent_topology = each_adjacent_topology.rstrip('\n')
            if each_adjacent_topology != '\n':
                # Check if we are reading the adjacent nodes for the current node
                current_topology = each_adjacent_topology.split(" ")
                # print(current_topology)

                source_ip, source_port = current_topology[0].split(',')

                full_network_topology.add(tuple([source_ip, int(source_port)]))

                if source_ip == self_name or source_ip == self_ip:
                    if int(source_port) == int(args.port):
                        # We are reading the topology for the current node -- add the nodes to the in-mem cache
                        for index in range(1, len(current_topology)):
                            this_node_ip, this_node_port = current_topology[index].split(",")
                            if this_node_ip == self_ip and int(this_node_port) == args.port:
                                continue
                            my_adjacent_nodes.append(tuple([this_node_ip, int(this_node_port)]))
                        # my_adjacent_nodes.append([tuple(current_topology[index].split(",")) for index in range(1, len(current_topology))])
    # print("My adjacent nodes are {}".format(my_adjacent_nodes))
    # print("Full N/W topo: {}".format(full_network_topology))
    # 3. Initialize forwarding table (list of tuples)
    # Any tuple: ((dest_ip, dest_port), (next_hop_ip, next_hop_port), cost, isvalid)
    # The initial entry will be only the adjacent nodes

    fwd_table = []
    for each_node in full_network_topology:
        # print("This node is {}".format(each_node))
        # print("My adjacent nodes are {}".format(my_adjacent_nodes))
        # print("Is this current node in my adj list {}".format(each_node in my_adjacent_nodes))
        if (not (each_node in my_adjacent_nodes)) and (each_node != self_host):
            fwd_table.append([each_node, None, None])
    for adj_node in my_adjacent_nodes:
        if adj_node[0] == self_ip and adj_node[1] == args.port:
            continue                
        fwd_table.append([adj_node, adj_node, 1])
        helloTimestamps[adj_node] = 0
        largestSeqNoPerNode[adj_node] = 0
    print("\n\n The INITIAL forwarding table is as follows: ")
    print_fwd_table(fwd_table)
    if DEBUG_PRINT:
        print("\nThe adjacent nodes for me are: ")
        for adj_node in my_adjacent_nodes:
            print(f"{adj_node[0]}:{adj_node[1]}")

# TESTING
    """
    # print("\n".join(str(fwd_entry) for fwd_entry in fwd_table))
    link_state_vector = []
    lsv = "10.141.147.221:5000:1|10.141.147.221:6000:1"
    ip_port_cost_pairs = lsv.split("|")
    for each_pair in ip_port_cost_pairs:
        dest_ip_addr, dest_port, dest_cost = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port), int(dest_cost)])
    print(link_state_vector)

    update_fwd_table(fwd_table, link_state_vector, tuple(["10.141.147.221", 7000]))
    print_fwd_table(fwd_table)

    print("\n\n\n\nSimulate the case that an indirect node is gone\n")
    link_state_vector = []
    lsv = "10.141.147.221:6000:1"
    ip_port_cost_pairs = lsv.split("|")
    for each_pair in ip_port_cost_pairs:
        dest_ip_addr, dest_port, dest_cost = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port), int(dest_cost)])
    print(link_state_vector)
    update_fwd_table(fwd_table, link_state_vector, tuple(["10.141.147.221", 7000]))
    print_fwd_table(fwd_table)

    print("\n\n\n\nSimulate the case that the gone indirect node can be reached through other\n")
    link_state_vector = []
    lsv = "10.141.147.221:5000:1|10.141.147.221:7000:1"
    ip_port_cost_pairs = lsv.split("|")
    for each_pair in ip_port_cost_pairs:
        dest_ip_addr, dest_port, dest_cost = each_pair.split(":")
        link_state_vector.append([dest_ip_addr, int(dest_port), int(dest_cost)])
    print(link_state_vector)
    update_fwd_table(fwd_table, link_state_vector, tuple(["10.141.147.221", 6000]))
    print_fwd_table(fwd_table)
    """

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
        current_time = round(time() * 1000)
        try:
            # print(type(read_sock))
            data, addr = read_sock.recvfrom(4096)
        except BlockingIOError as bie:
            pass

        # If we receive a packet -> unpack the information from the received socket datagram
        if data:
        #     # TODO may need to change the implementation of the decapsulate based on the requirement
            priority, src_ip, src_port, dst_ip, dst_port, length, packet_type, seq_no, inner_len, inner_data = outer_payload_decapsulate(data)
        #     # Check what is the type of the message received
            source = tuple([src_ip, src_port])
            if DEBUG_PRINT:
                print(f"{source}, {packet_type}, {seq_no}")
            # Case A: It is a Data/End/Request packet -- forward to next hop
            if packet_type in ['D', 'E', 'R']:
                next_hop_found = False
                for each_fwd_entry in fwd_table:
                    # If the destination entry exists and the route is valid, fwd the packet to their next hop
                    if each_fwd_entry[FWD_TABLE_DEST_IDX] == tuple(dst_ip, dst_port):
                        next_hop_found = True
                        send_packet(data, each_fwd_entry[FWD_TABLE_NEXT_HOP_IDX][0], each_fwd_entry[FWD_TABLE_NEXT_HOP_IDX][1])
                        break
                if not next_hop_found:
                    print(f"Destination {dst_ip}:{dst_port} not found in fwd table."
                              " Dropping the packet.")
                    pass
            # Case B: If it is a HELLO packet from neighbour -> update the timestamp of Hello
            # TODO Should check if it is a neighbour or not?
            # TODO Verify from book if anything else is expected here
            elif packet_type == PACKET_TYPE_HELLO:
                if DEBUG_PRINT:
                    print(f"Received HELLO FROM MY NEIGHBOUR {source[0]}:{source[1]}")
                helloTimestamps[source] = current_time
                # print(helloTimestamps)
                # if (node, port) not in fwd_table (The node was unavailable till now)
                # Set the route to itself and set cost as 1 for the neighbour
                if not any(entry[FWD_TABLE_DEST_IDX] == source for entry in fwd_table):
                    fwd_table.append([source, source, 1])
                    # TODO check how many TTLs to send
                    send_link_state_message(my_adjacent_nodes, fwd_table, TTL, self_ip,args.port)
            # Case C: If a Link State message or RouteTrace or RouteTraceReply
            elif packet_type in [PACKET_TYPE_LINK_STATE, PACKET_TYPE_ROUTE_TRACE, PACKET_TYPE_ROUTE_TRACE_REPLY]:
                #   Check the LSN and check if newer than what we had. Discard if not            
                if largestSeqNoPerNode.get(source, 0) < seq_no:
                    # The sequence number is valid
                    largestSeqNoPerNode[source] = seq_no
                    #  TODO  Topology change == update the route topology and fwd_table
                    received_lsv = decode_link_state_vector(inner_data)
                    print(f"{source} SENT LSV -> {received_lsv}")
                    topology_changed = update_fwd_table(fwd_table, received_lsv, source)
                    if topology_changed:
                        #   Call forwardpacket to flood to neighbours
                        print("topology_changed: {}".format(topology_changed))
                        forward_packet(data, my_adjacent_nodes,fwd_table,self_ip,args.port) #TODO
                else:
                    pass
            pass

        # 3. Send the HelloMessage if timedelta has passed
        if current_time - myLastHello >= HELLO_MESSAGE_DELTA:
            for adj_node in my_adjacent_nodes:
                send_hello_message(self_ip, args.port, adj_node[0], adj_node[1])
            myLastHello = current_time

        # 4. Check the neighbors and update the fwd table as required
        deletion_entries = []
        for neighbour, lastHelloTS in helloTimestamps.items():
            if current_time - lastHelloTS > NO_MESSAGE_TOLERANCE*HELLO_MESSAGE_DELTA:
                # remove all the entries from the table for which this neighbour was the next hop
                # Rebuild (?) the fwd table
                for fwd_entry in fwd_table:
                    if (fwd_entry[FWD_TABLE_NEXT_HOP_IDX] == neighbour):
                        # If it is an immediate neighbour, do not delete the entry, as the next hop will be that node only
                        if fwd_entry[FWD_TABLE_DEST_IDX] in my_adjacent_nodes:
                            # print("HELLO not received from the adjacent neighbour {}".format(str(fwd_entry[FWD_TABLE_DEST_IDX])))
                            continue  
                        deletion_entries.append(fwd_entry)
                        fwd_entry[FWD_TABLE_NEXT_HOP_IDX] = None
                        fwd_entry[FWD_TABLE_COST_IDX] = None
                pass
        for each_entry in deletion_entries:
            # if DEBUG_PRINT:
            if each_entry[FWD_TABLE_NEXT_HOP_IDX] in largestSeqNoPerNode:
                del largestSeqNoPerNode[each_entry[FWD_TABLE_NEXT_HOP_IDX]]
        if deletion_entries:
            print("Removed the entries {} as no HELLO received from them. Updated forwarding table:".format(','.join(str(ent[0]) for ent in deletion_entries)))
            print_fwd_table(fwd_table)

        # 5. Send the newest LinkStateMessage to all neighbors if time has passed
        if current_time - myLastLSM > LINK_STATE_MSG_TIMEOUT:
            # if DEBUG_PRINT:
            print("Timeout occured for LSM. Resending the latest LSV")
            send_link_state_message(my_adjacent_nodes, fwd_table, TTL, self_ip,args.port)
        continue

