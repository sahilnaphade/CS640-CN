import argparse
# import logging
import socket
from time import time
from io import BlockingIOError
from utils import *
from copy import deepcopy
# from threading import Event, Thread

DEBUG_PRINT = False

# packet_is_being_delayed = False
NO_MESSAGE_TOLERANCE = 3 # Total count of misses before removing the entry
HELLO_MESSAGE_DELTA = 300 # in milliseconds (TBD)
LINK_STATE_MSG_TIMEOUT = 3000

aNodeWentDown = False
helloTimestamps = {}
largestSeqNoPerNode = {}
myLastHello = 0 # Timestamp of last hello message
myLastLSM = 0
myLSMSeqNo = 0
myLSN = 1
unreachable_nodes = []

LOG = None

def print_topology(whole_topo):
    table_dict = {}
    table = []
    print_topo = dict(sorted(whole_topo.items()))
    # print(print_topo)
    for entry, adjacents in print_topo.items():
        if entry in unreachable_nodes:
            continue
        if entry not in table_dict:
            table_dict[entry] = []
        # print("ENTRY: {} and adjacents: {}".format(entry, adjacents))
        for each in adjacents:
            if each[1] == True:
                table_dict[entry].append(each[0])

    print ("\n {:<27} {:<13}".format('Destination', 'Adjacents'))
    print(63*"#")
    for k, v in table_dict.items():
        print("{:<25} {}".format(str(k[0]) + " : " + str(k[1]), ", ".join(str(each[0]) + " : " + str(each[1]) for each in v)))
    print("\n")


def print_fwd_table(fwd_table):
    
    table_dict = {}
    table = []
    for entry in fwd_table:
        if entry[NEXT_HOP] is None or entry[DESTINATION] is None:
            table.append([entry[DESTINATION][0],entry[DESTINATION][1],None,None, entry[COST]])
        else:
            table.append([entry[DESTINATION][0],entry[DESTINATION][1],entry[NEXT_HOP][0],entry[NEXT_HOP][1], entry[COST]])

    for i in range(0,len(table)):
        table_dict[i] = table[i]

    print ("\n {:<15} {:<11} {:<15} {:<15} {:<5} ".format('Dest IP','Dest Port','Next Hop IP', 'Next Hop Port', 'Cost'))
    print(63*"#")
    for k, v in table_dict.items():
        dest_ip, dest_port, next_hop_ip, next_hop_port, cost = v
        print ("{:<15} {:<11} {:<15} {:<15} {:<5}".format(str(dest_ip), str(dest_port), str(next_hop_ip), str(next_hop_port), str(cost)))
    print("\n")

def send_hello_message(src_ip, src_port, dest_ip, dest_port, send_sock=None):
    global myLSN, myLastHello
    inner_pack = inner_payload_encapsulate(PACKET_TYPE_HELLO, myLSN, "", 0)
    final_pack = outer_payload_encapsulate(src_ip, src_port, dest_ip, dest_port, inner_pack)
    try:
        if send_sock is None:
            send_sock = socket.socket(socket.AF_INET, socket.AF_INET)
        send_sock.sendto(final_pack, (dest_ip, dest_port))
        myLastHello = round(time() * 1000)
        # if DEBUG_PRINT:
        # print(f"Sent hello to {dest_ip}:{dest_port} at time {myLastHello}")
    except Exception as ex:
        raise ex
    finally:
        myLSN += 1
    pass

def send_link_state_message(my_adj_nodes, fwd_table, route_topology, TTL,self_ip, port, send_sock=None):
    global myLastLSM, myLSMSeqNo
    myLSMSeqNo += 1
    try:
        if send_sock is None:
            send_sock = socket.socket(socket.AF_INET, # Internet
                    socket.SOCK_DGRAM) # UDP
        for node in my_adj_nodes:
            payload = generate_link_state_vector(fwd_table, route_topology, my_adj_nodes, node) # Will encode the only the adjacent node states
            # if DEBUG_PRINT:
            # print(f"My LSV sent to the node {node} is :  {payload}")
            inner_payload = inner_payload_encapsulate(PACKET_TYPE_LINK_STATE, myLSMSeqNo, payload, TTL) # payload length in the inner header is TTL
            packet = outer_payload_encapsulate(self_ip,port, node[0], node[1], inner_payload)
            send_sock.sendto(packet,(node[0],node[1]))
        myLastLSM = round(time() * 1000)
        if DEBUG_PRINT:
            print(f"Sending the LinkStateMessage to the neighbours at time {myLastLSM} \n")
    except Exception as ex:
        raise ex

def forwardpacket(data, my_adjacent_nodes,fwd_table,self_ip,self_port):
    send_socket = None
    priority,src_ip,src_port,dest_ip,dest_port,length,packet_type,seq_no,current_TTL,payload = outer_payload_decapsulate(data)
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
                if DEBUG_PRINT:
                    print("TTL is 0. Not forwarding the LSM packet")
                pass
        elif packet_type == PACKET_TYPE_ROUTE_TRACE:
            print("Got Route Trace packet \n")
            # Check if current_TTL is zero, if yes then need to send the route trace reply packet to the route trace applicaiton
            # with src ip and port of its own and dest ip and port of the route trace packet
            if current_TTL == 0:
                decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
                next_hop_for_packet = decoded_payload[0]

                inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
                packet = outer_payload_encapsulate(self_ip,self_port,dest_ip,dest_port,inner_payload)

                # send reply packet back to the route trace applicaiton.
                send_socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]) )
                if DEBUG_PRINT:
                    print(f"The TTL for the route trace is 0. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the LSV is {' <- '.join((str(each) for each in decoded_payload))}")
            else :
                if (dest_ip,dest_port) == (self_ip,self_port):
                    print("Got the route trace packet with my destination.. Sending the reply \n")
                    decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
                    #current_TTL = current_TTL - 1 # Total number of hops, as we append all the IP:port to the payload
                    next_hop_for_packet = decoded_payload[0]
                    
                    inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
                    packet = outer_payload_encapsulate(self_ip,self_port,dest_ip,dest_port,inner_payload)
                    if DEBUG_PRINT:
                        print(f"Reply packet. Forwarding towards sender. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the payload is {payload}")
                    # send reply packet back to the route trace applicaiton.
                    send_socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]))
                else :
                    for entry in fwd_table:                    
                        if entry[DESTINATION] == (dest_ip,dest_port): # Check the nexthop for the destination in the forwarding table
                            if entry[NEXT_HOP] is None: # The node went down and cannot be reached from this node, reply back to the routetrace
                                if DEBUG_PRINT:
                                    print("The destination {} requested by the route trace cannot be reached from this node.".format(entry[DESTINATION]))
                                decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
                                next_hop_for_packet = decoded_payload[0]

                                inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload+";UNREACHABLE",current_TTL)    
                                packet = outer_payload_encapsulate(self_ip,self_port,dest_ip,dest_port,inner_payload)

                                # send reply packet back to the route trace applicaiton.
                                send_socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]) )
                            else:
                                current_TTL -= 1  # decrement the TTL and create new packet and send to the next hop.

                                # Update own info to the payload (for the next hop while returning)
                                # This will follow the same format as standard package, except COST
                                #payload = append_own_send_info(payload, self_ip, self_port)
                                inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE,0,payload,current_TTL)
                                
                                packet = outer_payload_encapsulate(src_ip,src_port,dest_ip,dest_port,inner_payload)
                                send_socket.sendto(packet,(entry[NEXT_HOP][0],entry[NEXT_HOP][1]))
                                if DEBUG_PRINT:
                                    print(f"The TTL for the route trace is {current_TTL}. Forwarding to the next HOP @ {entry[NEXT_HOP][0]}:{entry[NEXT_HOP][1]}, the payload is {payload}")
                            break
    except Exception as ex:
        raise (ex)
    finally:
        if send_socket is not None:
            send_socket.close()

def buildForwardTable(fwd_table, my_adjacent_nodes, whole_topo, self_info):
    global unreachable_nodes
    for each_fwd_entry in fwd_table:
        dest = each_fwd_entry[DESTINATION]
        if dest not in my_adjacent_nodes:
            # if the destination is not reachable from LSV info, mark the next hop and the cost as None
            if dest in unreachable_nodes:
                each_fwd_entry[NEXT_HOP] = None
                each_fwd_entry[COST] = None
                continue
            # For others, calculate the path and cost
            visited = {}
            queue = [[ self_info ]]
            # print(type(queue))
            # print(type(queue[0]))
            found = False
            while queue:
                path = queue.pop(0)
                node = path[-1]
                # print(f"Searching the node {node} for the destination {dest}")
                if visited.get(node, False) == False:
                    neighbours = whole_topo[node]
                    for neighbor in neighbours:
                        if neighbor[1] == True: # The neighbours are reachable
                            new_path = deepcopy(path)
                            new_path.append(neighbor[0])
                            queue.append(list(new_path))
                        if neighbor[0] == dest:
                            found = True
                            break
                    visited[node] = True
                    if found:
                        break
            if found:
                final_path = queue[-1]
                each_fwd_entry[NEXT_HOP] = final_path[1]
                each_fwd_entry[COST] = len(final_path) - 1 # As we also store the current node's info
            else:
                each_fwd_entry[NEXT_HOP] = None
                each_fwd_entry[COST] = None


def readtopology(topology_file, self_ip, self_name, self_host, my_adjacent_nodes, full_network_topology, port):
    global unreachable_nodes
    whole_topo = {}
    with open(topology_file, "r") as topo_file:
 
        for each_adjacent_topology in topo_file:
            each_adjacent_topology = each_adjacent_topology.rstrip('\n')
            if each_adjacent_topology != '\n':
                # Check if we are reading the adjacent nodes for the current node
                current_topology = each_adjacent_topology.split(" ")
                source_ip, source_port = current_topology[0].split(',')

                whole_topo[tuple([source_ip, int(source_port)])] = []
                unreachable_nodes.append(tuple([source_ip, int(source_port)]))
                for index in range(1, len(current_topology)):
                    this_node_ip, this_node_port = current_topology[index].split(",")
                    this_node_ip = socket.gethostbyname(this_node_ip)
                    whole_topo[tuple([source_ip, int(source_port)])].append([tuple([this_node_ip, int(this_node_port)]), False])

                full_network_topology.add(tuple([source_ip, int(source_port)]))

                if source_ip == self_name:
                    source_ip = socket.gethostbyname(source_ip)
                if source_ip == self_ip:
                    if int(source_port) == int(args.port):
                        unreachable_nodes.remove(tuple([source_ip, int(source_port)]))
                        # We are reading the topology for the current node -- add the nodes to the in-mem cache
                        for index in range(1, len(current_topology)):
                            this_node_ip, this_node_port = current_topology[index].split(",")
                            this_node_ip = socket.gethostbyname(this_node_ip)
                            if this_node_ip == self_ip and int(this_node_port) == args.port:
                                continue
                            my_adjacent_nodes.append(tuple([this_node_ip, int(this_node_port)]))

    for each_dest, its_neighbours in whole_topo.items():
        for each in its_neighbours:
            if each[0] == tuple([self_ip, int(args.port)]):
                each[1] = True

    # print(f"WHOLE TOPO IS {whole_topo}")

    # print(f"unreachable_nodes are as follows:: {unreachable_nodes}")
    # 3. Initialize forwarding table (list of tuples)
    # Any tuple: ((dest_ip, dest_port), (next_hop_ip, next_hop_port), cost, isvalid)
    # The initial entry will be only the adjacent nodes
    route_topology = {}
    fwd_table = []
    for each_node in full_network_topology:
        if (not (each_node in my_adjacent_nodes)) and (each_node != self_host):
            fwd_table.append([each_node, None, None])
            route_topology[each_node] = []
    for adj_node in my_adjacent_nodes:
        if adj_node[0] == self_ip and adj_node[1] == port:
            continue
        fwd_table.append([adj_node, adj_node, 1])
        route_topology[adj_node] = [adj_node]
        helloTimestamps[adj_node] = 0
        largestSeqNoPerNode[adj_node] = 0
    TTL = len(fwd_table)
    print(f"\n\n The Initial Forwarding table is: ")
    print_fwd_table(fwd_table)
    if DEBUG_PRINT:
        print("\nThe adjacent nodes for me are: ")
        for adj_node in my_adjacent_nodes:
            print(f"{adj_node[0]}:{adj_node[1]}")
    return route_topology, fwd_table, helloTimestamps, largestSeqNoPerNode, TTL, whole_topo

def createroutes(self_name, self_ip, self_port, my_adjacent_nodes, full_network_topology, route_topology, fwd_table, helloTimestamps, largestSeqNoPerNode, TTL, whole_topo):
    global myLastHello, myLastLSM, myLSMSeqNo, myLSN, unreachable_nodes
    read_sock = None
    send_sock = None
    my_info = tuple([self_ip, int(self_port)])
    try:
        read_sock = socket.socket(socket.AF_INET, # Internet
                            socket.SOCK_DGRAM) # UDP
    except Exception as ex:
        raise ex
    try:
        send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
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
            priority, src_ip, src_port, dst_ip, dst_port, length, packet_type, seq_no, inner_len, inner_data = outer_payload_decapsulate(data)
        #     # Check what is the type of the message received
            source = tuple([src_ip, int(src_port)])
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
                    print(f"Destination {dst_ip}:{dst_port} not found in fwd table for the packet of type {packet_type} from {source}."
                              " Dropping the packet.")
                    pass
            # Case B: If it is a HELLO packet from neighbour -> update the timestamp of Hello
            elif packet_type == PACKET_TYPE_HELLO:
                # if DEBUG_PRINT:
                # print(f"Received HELLOs FROM MY NEIGHBOUR {source[0]}:{source[1]}")
                # If the neighbour was considered down for some time, update the cost and the next hop for that node
                if helloTimestamps.get(source, 0) == 0 and source in my_adjacent_nodes:
                    for fwd_entry in fwd_table:
                        if fwd_entry[DESTINATION] == source:
                            fwd_entry[COST] = 1
                            route_topology[source] = [source]
                            print("Topology changed. Node {} is now reachable. Current FWD table".format(source))
                            # Update the cached topology for the previously unreachable node
                            for dest, adjacents in whole_topo.items():
                                for each_node in adjacents:
                                    if each_node[0] == source:
                                        each_node[1] = True
                            if source in unreachable_nodes:
                                unreachable_nodes.remove(source)
                            buildForwardTable(fwd_table, my_adjacent_nodes, whole_topo, my_info)
                            print_fwd_table(fwd_table)
                            print_topology(whole_topo)
                            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip, args.port, send_sock=send_sock)
                            break
                helloTimestamps[source] = current_time
                # print(helloTimestamps)
            # Case C: If a Link State message or RouteTrace or RouteTraceReply
            elif packet_type in [PACKET_TYPE_LINK_STATE]:
                # If a node received its own (old) LSM which is more than the current LSM (the node went down), update it to the latest value
                # And discard the packet
                if source == my_info:
                    if myLSMSeqNo < seq_no:
                        myLSMSeqNo = seq_no
                        continue
                #   Check the LSN and check if newer than what we had. Discard if not            
                if largestSeqNoPerNode.get(source, 0) < seq_no:
                    # The sequence number is valid
                    largestSeqNoPerNode[source] = seq_no
                    # TODO Topology change == update the route topology and fwd_table
                    received_lsv = decode_link_state_vector(inner_data)
                    if received_lsv is None:
                        pass
                    else:
                        # print(f"{source} sent the LSV -> {received_lsv}")
                        topo_updated = False
                        # Handle the LSV and see if the topology is getting updated
                        for each_lsv_entry in received_lsv:
                            dest_ip_port = each_lsv_entry[0]
                            dest_cost_from_the_lsv_node = each_lsv_entry[1]
                            # dest_path_from_the_lsv_node = each_lsv_entry[3]
                            # If the LSM says that a node has died -- update the topology, and add to unreachable nodes
                            if dest_cost_from_the_lsv_node is None:
                                if dest_ip_port not in unreachable_nodes:
                                    unreachable_nodes.append(dest_ip_port)
                                    if dest_ip_port in largestSeqNoPerNode:
                                        del largestSeqNoPerNode[dest_ip_port]
                                    topo_updated = True
                                for dest, adjacents in whole_topo.items():
                                    for each in adjacents:
                                        if each[0] == dest_ip_port:
                                            each[1] = False
                                buildForwardTable(fwd_table, my_adjacent_nodes, whole_topo, my_info)
                            else:
                                if dest_ip_port in unreachable_nodes:
                                    unreachable_nodes.remove(dest_ip_port)
                                    topo_updated = True
                                for dest, adjacents in whole_topo.items():
                                    for each in adjacents:
                                        if each[0] == dest_ip_port:
                                            each[1] = True
                                buildForwardTable(fwd_table, my_adjacent_nodes, whole_topo, my_info)
                        forwardpacket(data, my_adjacent_nodes, fwd_table, self_ip, args.port)
                        if topo_updated:
                            print_fwd_table(fwd_table)
                else:
                    pass
            elif packet_type in [PACKET_TYPE_ROUTE_TRACE, PACKET_TYPE_ROUTE_TRACE_REPLY]:
                forwardpacket(data, my_adjacent_nodes,fwd_table,self_ip,args.port)
                pass
            pass

        # 3. Send the HelloMessage if timedelta has passed
        if current_time - myLastHello >= HELLO_MESSAGE_DELTA:
            for adj_node in my_adjacent_nodes:
                send_hello_message(self_ip, args.port, adj_node[0], adj_node[1], send_sock=send_sock)
            myLastHello = current_time

        # 4. Check the neighbors and update the fwd table and topology as required
        deletion_entries = []
        topology_changed = False
        for neighbour, lastHelloTS in helloTimestamps.items():
            if current_time - lastHelloTS > NO_MESSAGE_TOLERANCE*HELLO_MESSAGE_DELTA:
                aNodeWentDown = True
                # Update the cached topology and the forwarding table for the newly unreachable node
                helloTimestamps[neighbour] = 0
                if neighbour not in unreachable_nodes:
                    unreachable_nodes.append(neighbour)
                for dest, adjacents in whole_topo.items():
                    for each_node in adjacents:
                        if each_node[0] == neighbour:
                            each_node[1] = False
                for fwd_entry in fwd_table:
                    if (fwd_entry[NEXT_HOP] == neighbour):
                        # If it is an immediate neighbour, do not delete the next hop
                        # as the next hop will be that node only
                        fwd_entry[COST] = None
                        deletion_entries.append(fwd_entry)
                        if fwd_entry[DESTINATION] in my_adjacent_nodes:
                            topology_changed = True
                            print("Updated the adjacent node {} as no HELLO received from them.".format(fwd_entry[DESTINATION]))
                            buildForwardTable(fwd_table, my_adjacent_nodes, whole_topo, my_info)
                            continue
                        else:
                            print("Updated the destination {} as the next hop {} is down.".format(fwd_entry[DESTINATION], fwd_entry[NEXT_HOP]))
                            fwd_entry[NEXT_HOP] = None
                            topology_changed = True
                            buildForwardTable(fwd_table, my_adjacent_nodes, whole_topo, my_info)
                            continue
                topo_clear = []
                for dest, path_entries in route_topology.items():
                    if neighbour in path_entries:
                        topo_clear.append(dest)
                for each_tuple in topo_clear:
                    route_topology[each_tuple] = []
                route_topology[neighbour] = []
        # Since we know that the node is unreachable, update the hello timestamps for that neighbour as well as the largest seq no received till now.
        for each_entry in deletion_entries:
            if each_entry[NEXT_HOP] in helloTimestamps:
                del helloTimestamps[each_entry[NEXT_HOP]]
            if each_entry[NEXT_HOP] in largestSeqNoPerNode:
                del largestSeqNoPerNode[each_entry[NEXT_HOP]]
        # if deletion_entries:
        #     print("The forwarding table and route topology:")
        #     print_fwd_table(fwd_table)
        #     print_topology(whole_topo)
        if topology_changed:
            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip, args.port)
            print_fwd_table(fwd_table)
            print_topology(whole_topo)

        # 5. Send the newest LinkStateMessage to all neighbors if timeout has occurred
        if current_time - myLastLSM > LINK_STATE_MSG_TIMEOUT:
            if DEBUG_PRINT:
                print("Timeout occured for LSM. Resending the latest LSV")
            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip,args.port)
        continue

  
            
if __name__ == "__main__":
    # 1. Parse arguments
    parser = argparse.ArgumentParser(description="Emulates network for UDP")
    parser.add_argument("-p", "--port", dest="port", type=int, required=True, help="Port on which the emulator runs")
    parser.add_argument("-f", "--filename", dest="topology_file", type=str, required=True, help="File containing information about the static forwarding table")

    args = parser.parse_args()

    # 3. Read the topology and get the immediately adjacent nodes of current node
    self_name = socket.gethostname()
    self_ip = socket.gethostbyname(self_name)
    my_adjacent_nodes = []
    self_host = tuple([self_ip, int(args.port)])
    full_network_topology = set() # List of all nodes in the current network

    route_topology, fwd_table, helloTimestamps, largestSeqNoPerNode, TTL, whole_topo = readtopology(args.topology_file,self_ip, self_name, self_host, my_adjacent_nodes, full_network_topology, args.port)
    
    if DEBUG_PRINT:
        print("My neighbour nodes are:")
        for adj in my_adjacent_nodes:
            print(adj)
        print("\n")
    createroutes(self_name, self_ip, args.port, my_adjacent_nodes, full_network_topology, route_topology, fwd_table, helloTimestamps, largestSeqNoPerNode, TTL, whole_topo)

