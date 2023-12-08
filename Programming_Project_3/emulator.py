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

DEBUG_PRINT = 1

# packet_is_being_delayed = False
NO_MESSAGE_TOLERANCE = 3 # Total count of misses before removing the entry
HELLO_MESSAGE_DELTA = 3000 # in milliseconds (TBD)
LINK_STATE_MSG_TIMEOUT = 3000

aNodeWentDown = False
helloTimestamps = {}
largestSeqNoPerNode = {}
myLastHello = 0 # Timestamp of last hello message
myLastLSM = 0
myLSMSeqNo = 0
myLSN = 1

def print_fwd_table(fwd_table):
    print(['   Dest IP  ', 'Dest Port', 'Next Hop IP', "Next hop port", "Cost"])
    for entry in fwd_table:
        destination = entry[DESTINATION]
        next_hop = entry[NEXT_HOP]
        cost = entry[COST]
        if next_hop == None:
            print([destination[0], "  "+str(destination[1])+"   ", "None", "None", cost])
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
        raise ex
    finally:
        if send_sock is not None:
            send_sock.close()
        myLSN += 1
    pass

def send_link_state_message(my_adj_nodes, fwd_table, route_topology, TTL,self_ip, port):  #TODO : check if we are incrementing TTL when calling this function amid topology change
    global myLastLSM, myLSMSeqNo
    myLSMSeqNo += 1
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
        for node in my_adj_nodes:
            payload = generate_link_state_vector(fwd_table, route_topology, node) # Will encode the full forwarding table until then as payload
            print(payload)
            inner_payload = inner_payload_encapsulate(PACKET_TYPE_LINK_STATE, myLSMSeqNo, payload, TTL) # payload length in the inner header is TTL
            #Iterate through all the adjacent nodes and send the forwarding table
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
    send_socket = None
    priority,src_ip,src_port,dest_ip,dest_port,length,packet_type,seq_no,current_TTL,payload = outer_payload_decapsulate(data)
    print(f"This is the TTL from packet : {current_TTL} \n\n\n\n")
    try:
        send_socket = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
        if packet_type == PACKET_TYPE_LINK_STATE:
            if current_TTL > 0:
                current_TTL -= 1
                inner_payload = inner_payload_encapsulate(PACKET_TYPE_LINK_STATE, seq_no, payload, current_TTL)
                for node in my_adjacent_nodes:
                    # DO not forward the packet back to the node from which we received it
                    if src_ip == node[0] and int(src_port) == int(node[1]):
                        continue
                    packet = outer_payload_encapsulate(src_ip, src_port, node[0], node[1], inner_payload)
                    send_socket.sendto(packet,(node[0], node[1]))
            elif current_TTL == 0:
                if DEBUG_PRINT == 1:
                    print("TTL is 0. Not forwarding the LSM packet")
                pass
        elif packet_type == PACKET_TYPE_ROUTE_TRACE:
            print("Got Route Trace packet \n\n")
            # Check if current_TTL is zero, if yes then need to send the route trace reply packet to the route trace applicaiton
            # with src ip and port of its own and dest ip and port of the route trace packet
            if current_TTL == 0:
                print("TTL is 0 so replying back.....\n\n\n\n\n")
                decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
                #current_TTL = len(decoded_payload) # Total number of hops, as we append all the IP:port to the payload
                next_hop_for_packet = decoded_payload[0]
                
                # payload = append_own_send_info(payload, self_ip, self_port)
                inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
                packet = outer_payload_encapsulate(self_ip,self_port,dest_ip,dest_port,inner_payload)
                
                # send reply packet back to the route trace applicaiton.
                send_socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]) )
                if DEBUG_PRINT == 0:
                
                    print(f"The TTL for the route trace is 0. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the LSV is {' <- '.join(str((decoded_payload)))}")
                
                #TODO : Need to verify packet format consistency with the project requirements : source port, ip
            else :
                print(f"TTL is {current_TTL}\n\n\n")
                if (dest_ip,dest_port) == (self_ip,self_port):
                    print("Got the route trace packet with my destination.. Sending the reply \n\n")
                    decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
                    #current_TTL = current_TTL - 1 # Total number of hops, as we append all the IP:port to the payload
                    next_hop_for_packet = decoded_payload[0]
                    
                    
                    inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
                    packet = outer_payload_encapsulate(self_ip,self_port,dest_ip,dest_port,inner_payload)
                    if DEBUG_PRINT == 0:
                        print(f"Reply packet. Forwarding towards sender. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the payload is {payload}")
                    # send reply packet back to the route trace applicaiton.
                    send_socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]))
                else :
                    for entry in fwd_table:                    
                        if entry[DESTINATION] == (dest_ip,dest_port): # Check the nexthop for the destination in the forwarding table
                            current_TTL -= 1  # decrement the TTL and create new packet and send to the next hop.
                            print(f"TTL Decremented : {current_TTL} \n\n\n")
                            # Update own info to the payload (for the next hop while returning)
                            # This will follow the same format as standard package, except COST
                            #payload = append_own_send_info(payload, self_ip, self_port)

                            inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE,0,payload,current_TTL)
                            
                            packet = outer_payload_encapsulate(src_ip,src_port,dest_ip,dest_port,inner_payload)
                            send_socket.sendto(packet,(entry[NEXT_HOP][0],entry[NEXT_HOP][1]))
                            if DEBUG_PRINT == 0:
                                print(f"The TTL for the route trace is {current_TTL}. Forwarding to the next HOP @ {entry[NEXT_HOP][0]}:{entry[NEXT_HOP][1]}, the payload is {payload}")
                            break
        # elif packet_type == PACKET_TYPE_ROUTE_TRACE_REPLY:
        #     # If the packet is simply going back, get the last TTLth record in the payload, that will be our next hop
        #     # TODO check
        #     decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
        #     print(f"Decoded Paylaod {decoded_payload}\n\n")
        #     #current_TTL = current_TTL - 1 # Total number of hops, as we append all the IP:port to the payload
        #     print(current_TTL)
        #     next_hop_for_packet = decoded_payload[0]
        #     print(f"Next hop from packet {next_hop_for_packet} \n\n")
        #     payload = append_own_send_info(payload, self_ip, self_port)
        #     inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
        #     packet = outer_payload_encapsulate(self_ip,self_port,dest_ip,dest_port,inner_payload)
        #     if DEBUG_PRINT == 0:
        #         print(f"Reply packet. Forwarding towards sender. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the payload is {payload}")
        #     # send reply packet back to the route trace applicaiton.
        #     send_socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]) )
    except Exception as ex:
        raise (ex)
    finally:
        if send_socket is not None:
            send_socket.close()


# Souce of LSV will always be the immediate adjacent == cost will increment by 1
def update_fwd_table(fwd_table, received_lsv, source_of_lsv, my_adjacent_nodes, route_topology):
    global helloTimestamps

    global aNodeWentDown
    if DEBUG_PRINT == 2:
        print("Current FWD table is {}".format(fwd_table))
    topo_updated = False
    for each_lsv_entry in received_lsv:
        dest_ip_port = tuple([each_lsv_entry[0], int(each_lsv_entry[1])])
        dest_cost = each_lsv_entry[2]
        dest_path = each_lsv_entry[3]
        for each_fwd_entry in fwd_table:
            # If we find the entry in the LSDB
            current_cost = None if each_fwd_entry[COST] is None else each_fwd_entry[COST]
            incoming_cost = None if dest_cost is None else (int(dest_cost) + 1) # As the LSV is from the immediate neighbour

            if each_fwd_entry[DESTINATION] == dest_ip_port:
                # Special case, if the destination in the received LSV is actually adjacent for the current node
                # The cost should be 1 for the destination and should not be updated
                if dest_ip_port in my_adjacent_nodes:
                    continue
                # If the next hop is still same for a dest but the cost has changed
                #   we only update the cost to the new one (as other topology beyond might have changed)
                # Later if we receive something lower from a different node, then we change it at that point for that node LSV
                if each_fwd_entry[NEXT_HOP] == source_of_lsv:
                    # Update only if the cost is different
                    #   If the destination node is unreachable from the next hop, mark the next hop as None
                    if incoming_cost is None:
                        each_fwd_entry[NEXT_HOP] = None
                        topo_updated = True
                        if source_of_lsv in route_topology[dest_ip_port]:
                            route_topology[dest_ip_port] = []
                        break
                    if each_fwd_entry[COST] != incoming_cost:
                        each_fwd_entry[COST] = incoming_cost
                        topo_updated = True
                        break
                else:
                    # If the LSV says it can reach the destination through a different node with lower cost, we update
                    #   First, if the node was previously unreachable and still is unreachable, we dont update
                    # We update the costs to new only depending on the cost from the immediately adjacent node
                    if source_of_lsv in my_adjacent_nodes:
                        if incoming_cost is None and current_cost is None:
                            continue
                        #   If previously unreachable, but now reachable, we use it
                        if (incoming_cost is not None and current_cost is None):
                            if incoming_cost != len(each_lsv_entry[3]) + 1:
                                route_topology[dest_ip_port] = []
                                break
                            each_fwd_entry[COST] = incoming_cost
                            each_fwd_entry[NEXT_HOP] = source_of_lsv
                            print("SAHIL Attaching the address: {} -> {}".format(dest_ip_port, route_topology[dest_ip_port]))
                            route_topology[dest_ip_port] = each_lsv_entry[3]    
                            if dest_ip_port not in route_topology[dest_ip_port]:
                                route_topology[dest_ip_port].append(dest_ip_port)
                            if source_of_lsv not in route_topology[dest_ip_port]:
                                route_topology[dest_ip_port].append(source_of_lsv)
                            topo_updated = True
                            continue
                        #   If previously reachable, but this node cannot be reached through the adjacent node
                        if (incoming_cost is None and current_cost is not None):
                            # if current_cost != len(each_lsv_entry[3]) + 1:
                            #     route_topology[dest_ip_port] = []
                            if each_fwd_entry[NEXT_HOP] == source_of_lsv:
                                aNodeWentDown = True
                                each_fwd_entry[COST] = None
                                each_fwd_entry[NEXT_HOP] = None
                                topo_updated = True
                                dests_to_be_updated = []
                                for dest, path in route_topology.items():
                                    if dest_ip_port in path:
                                        dests_to_be_updated.append(dest)
                                for destination in dests_to_be_updated:
                                    route_topology[destination] = []
                                continue
                            else:
                                continue
                        #   If was reachable and from the new node also reachable, check if the cost is lower. Update if yes
                        if incoming_cost != current_cost:
                            if incoming_cost < current_cost:
                                each_fwd_entry[COST] = incoming_cost
                                old_next_hop = each_fwd_entry[NEXT_HOP]
                                route_topology[dest_ip_port].remove(old_next_hop)
                                each_fwd_entry[NEXT_HOP] = source_of_lsv
                                if source_of_lsv not in route_topology[dest_ip_port]:
                                    route_topology[dest_ip_port].append(source_of_lsv)
                                if DEBUG_PRINT:
                                    print("Incoming cost for the destination {} is {}, "
                                        "existing cost is {}. Updated the entry."
                                        .format(dest_ip_port, incoming_cost, current_cost))
                                topo_updated = True
                    else:
                        pass
    all_stabilized = all(x[COST] is not None for x in fwd_table)
    if aNodeWentDown and not topo_updated:
        print("\n\nAll routes have stabilized after 1(or more) node(s) went down!\n\n")
        print_fwd_table(fwd_table)
        aNodeWentDown = False
    elif all_stabilized and topo_updated:
        print("\n\nAll routes have stabilized now!\n\n")
        print_fwd_table(fwd_table)
        print("\n\n")
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
    # self_name = socket.gethostname()
    self_name = "localhost"
    self_ip = "127.0.0.1"    
    my_adjacent_nodes = []
    self_host = tuple([self_ip, int(args.port)])
    full_network_topology = set() # List of all nodes in the current network
    TTL = 5

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
    route_topology = {}
    fwd_table = []
    for each_node in full_network_topology:
        # print("This node is {}".format(each_node))
        # print("My adjacent nodes are {}".format(my_adjacent_nodes))
        # print("Is this current node in my adj list {}".format(each_node in my_adjacent_nodes))
        if (not (each_node in my_adjacent_nodes)) and (each_node != self_host):
            fwd_table.append([each_node, None, None])
            route_topology[each_node] = []
    for adj_node in my_adjacent_nodes:
        if adj_node[0] == self_ip and adj_node[1] == args.port:
            continue
        fwd_table.append([adj_node, adj_node, 1])
        route_topology[adj_node] = [adj_node]
        helloTimestamps[adj_node] = 0
        largestSeqNoPerNode[adj_node] = 0
    print("ROUTE TOPOLOGY IS : {}", route_topology)
    print("\n\n The INITIAL forwarding table is as follows: ")
    print_fwd_table(fwd_table)
    if DEBUG_PRINT:
        print("\nThe adjacent nodes for me are: ")
        for adj_node in my_adjacent_nodes:
            print(f"{adj_node[0]}:{adj_node[1]}")
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
            source = tuple([src_ip, int(src_port)])
            if DEBUG_PRINT == 2:
                print(f"{source}, {packet_type}, {seq_no}")
            # Case A: It is a Data/End/Request packet -- forward to next hop
            if packet_type in ['D', 'E', 'R']:
                next_hop_found = False
                for each_fwd_entry in fwd_table:
                    # If the destination entry exists and the route is valid, fwd the packet to their next hop
                    if each_fwd_entry[DESTINATION] == tuple(dst_ip, int(dst_port)):
                        next_hop_found = True
                        send_packet(data, each_fwd_entry[NEXT_HOP][0], each_fwd_entry[NEXT_HOP][1])
                        break
                if not next_hop_found:
                    print(f"Destination {dst_ip}:{dst_port} not found in fwd table."
                              " Dropping the packet.")
                    pass
            # Case B: If it is a HELLO packet from neighbour -> update the timestamp of Hello
            # TODO Should check if it is a neighbour or not?
            # TODO Verify from book if anything else is expected here
            elif packet_type == PACKET_TYPE_HELLO:
                if DEBUG_PRINT == 2:
                    print(f"Received HELLO FROM MY NEIGHBOUR {source[0]}:{source[1]}")
                if helloTimestamps.get(source, 0) == 0 and source in my_adjacent_nodes:
                    for fwd_entry in fwd_table:
                        if fwd_entry[DESTINATION] == source:
                            fwd_entry[COST] = 1
                            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip, args.port)
                            print("Topology changed. Node {} is now reachable. Current FWD table")
                            print_fwd_table(fwd_table)
                            break
                helloTimestamps[source] = current_time
                # print(helloTimestamps)
                # if (node, port) not in fwd_table (The node was unavailable till now)
                # Set the route to itself and set cost as 1 for the neighbour
                if not any(entry[DESTINATION] == source for entry in fwd_table):
                    fwd_table.append([source, source, 1])
                    # TODO check how many TTLs to send
                    send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip,args.port)
                route_topology[source] = [source]
            # Case C: If a Link State message or RouteTrace or RouteTraceReply
            elif packet_type in [PACKET_TYPE_LINK_STATE]:
                #   Check the LSN and check if newer than what we had. Discard if not            
                if largestSeqNoPerNode.get(source, 0) < seq_no:
                    # The sequence number is valid
                    largestSeqNoPerNode[source] = seq_no
                    # TODO Topology change == update the route topology and fwd_table
                    received_lsv = decode_link_state_vector(inner_data)
                    if DEBUG_PRINT == 1:
                        print(f"The source {source}     SENT LSV -> {received_lsv}\n\n")
                        print(largestSeqNoPerNode)
                    topology_changed = False
                    if inner_len >= 1: # Now we will decrement the TTL of the packet
                        topology_changed = update_fwd_table(fwd_table, received_lsv, source, my_adjacent_nodes, route_topology)
                        if topology_changed:
                            #   Call forwardpacket to flood to neighbours
                            print("topology_changed: The route topo is {}".format(route_topology))
                            forward_packet(data, my_adjacent_nodes, fwd_table, self_ip, args.port) #TODO
                    print("ROUTE TOPOLOGY NOW IS ::: {}".format(route_topology))
                else:
                    pass
            elif packet_type in [PACKET_TYPE_ROUTE_TRACE, PACKET_TYPE_ROUTE_TRACE_REPLY]:
                forward_packet(data, my_adjacent_nodes,fwd_table,self_ip,args.port) #TODO
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
                aNodeWentDown = True
                helloTimestamps[neighbour] = 0
                for fwd_entry in fwd_table:
                    if (fwd_entry[NEXT_HOP] == neighbour):
                        # If it is an immediate neighbour, do not delete the next hop
                        # as the next hop will be that node only
                        if fwd_entry[DESTINATION] in my_adjacent_nodes:
                            fwd_entry[COST] = None
                            deletion_entries.append(fwd_entry)
                            continue  
                        deletion_entries.append(fwd_entry)
                        fwd_entry[NEXT_HOP] = None
                        fwd_entry[COST] = None
                topo_clear = []
                for dest, path_entries in route_topology.items():
                    if neighbour in path_entries:
                        topo_clear.append(dest)
                for each_tuple in topo_clear:
                    route_topology[each_tuple] = []
                route_topology[neighbour] = []
        for each_entry in deletion_entries:
            if each_entry[NEXT_HOP] in helloTimestamps:
                del helloTimestamps[each_entry[NEXT_HOP]]
            if each_entry[NEXT_HOP] in largestSeqNoPerNode:
                del largestSeqNoPerNode[each_entry[NEXT_HOP]]
        if deletion_entries:
            print("Removed the entries {} as no HELLO received from them. Updated forwarding table:".format(','.join(str(ent[0]) for ent in deletion_entries)))
            print_fwd_table(fwd_table)

        # 5. Send the newest LinkStateMessage to all neighbors if time has passed
        if current_time - myLastLSM > LINK_STATE_MSG_TIMEOUT:
            if DEBUG_PRINT == 1:
                print("Timeout occured for LSM. Resending the latest LSV")
            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip,args.port)
        continue

