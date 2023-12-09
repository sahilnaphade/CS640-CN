import argparse
import logging
import socket
from time import time
from io import BlockingIOError
from utils import *
from threading import Event, Thread

DEBUG_PRINT = 0

# packet_is_being_delayed = False
NO_MESSAGE_TOLERANCE = 3 # Total count of misses before removing the entry
HELLO_MESSAGE_DELTA = 500 # in milliseconds (TBD)
LINK_STATE_MSG_TIMEOUT = 10000

aNodeWentDown = False
helloTimestamps = {}
largestSeqNoPerNode = {}
myLastHello = 0 # Timestamp of last hello message
myLastLSM = 0
myLSMSeqNo = 0
myLSN = 1

LOG = None


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
    
    print ("\n {:<11} {:<13} {:<13} {:<17} {:<13} ".format('Dest IP','Dest Port','Next Hop IP', 'Next Hop Port', 'Cost'))
    print(63*"#")
    for k, v in table_dict.items():
        dest_ip, dest_port, next_hop_ip, next_hop_port, cost = v
        print ("{:<14} {:<12} {:<16} {:<13} {:<14}".format(str(dest_ip), str(dest_port), str(next_hop_ip), str(next_hop_port), str(cost)))
    
    print("\n")

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
            if DEBUG_PRINT:
                print(f"My LSV is :  {payload}")
            inner_payload = inner_payload_encapsulate(PACKET_TYPE_LINK_STATE, myLSMSeqNo, payload, TTL) # payload length in the inner header is TTL
            #Iterate through all the adjacent nodes and send the forwarding table
            packet = outer_payload_encapsulate(self_ip,port,node[0],node[1],inner_payload)
            sock.sendto(packet,(node[0],node[1]))
        myLastLSM = round(time() * 1000)
        if DEBUG_PRINT:
            print(f"Sending the LinkStateMessage to the neighbours at time {myLastLSM} \n")
    except Exception as ex:
        raise ex
    finally:
        if sock is not None:
            sock.close()

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
                if DEBUG_PRINT == 1:
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
                if DEBUG_PRINT == 1:
                    print(f"The TTL for the route trace is 0. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the LSV is {' <- '.join(str((decoded_payload)))}")
                
            else :
                if (dest_ip,dest_port) == (self_ip,self_port):
                    print("Got the route trace packet with my destination.. Sending the reply \n")
                    decoded_payload = decode_lsv_route_trace(payload) # This will give the ip and port of route trace
                    #current_TTL = current_TTL - 1 # Total number of hops, as we append all the IP:port to the payload
                    next_hop_for_packet = decoded_payload[0]
                    
                    inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE_REPLY,0,payload,current_TTL)    
                    packet = outer_payload_encapsulate(self_ip,self_port,dest_ip,dest_port,inner_payload)
                    if DEBUG_PRINT == 1:
                        print(f"Reply packet. Forwarding towards sender. Replying back to the tracer @ {next_hop_for_packet[0]}:{next_hop_for_packet[1]}, the payload is {payload}")
                    # send reply packet back to the route trace applicaiton.
                    send_socket.sendto(packet, (next_hop_for_packet[0],next_hop_for_packet[1]))
                else :
                    for entry in fwd_table:                    
                        if entry[DESTINATION] == (dest_ip,dest_port): # Check the nexthop for the destination in the forwarding table
                            current_TTL -= 1  # decrement the TTL and create new packet and send to the next hop.

                            # Update own info to the payload (for the next hop while returning)
                            # This will follow the same format as standard package, except COST
                            #payload = append_own_send_info(payload, self_ip, self_port)
                            inner_payload = inner_payload_encapsulate(PACKET_TYPE_ROUTE_TRACE,0,payload,current_TTL)
                            
                            packet = outer_payload_encapsulate(src_ip,src_port,dest_ip,dest_port,inner_payload)
                            send_socket.sendto(packet,(entry[NEXT_HOP][0],entry[NEXT_HOP][1]))
                            if DEBUG_PRINT == 1:
                                print(f"The TTL for the route trace is {current_TTL}. Forwarding to the next HOP @ {entry[NEXT_HOP][0]}:{entry[NEXT_HOP][1]}, the payload is {payload}")
                            break
    except Exception as ex:
        raise (ex)
    finally:
        if send_socket is not None:
            send_socket.close()


# Souce of LSV will always be the immediate adjacent == cost will increment by 1
def build_ForwardTable(fwd_table, received_lsv, source_of_lsv, my_adjacent_nodes, route_topology):
    global helloTimestamps, LOG

    global aNodeWentDown
    if DEBUG_PRINT == 1:
        print("Current FWD table is {}".format(fwd_table))
    topo_updated = False
    if DEBUG_PRINT:
        print("Received the LSV {} from the source {}".format(received_lsv, source_of_lsv))
    for each_lsv_entry in received_lsv:
        dest_ip_port = tuple([each_lsv_entry[0], int(each_lsv_entry[1])])
        dest_cost_from_the_lsv_node = each_lsv_entry[2]
        dest_path_from_the_lsv_node = each_lsv_entry[3]
        for each_fwd_entry in fwd_table:
            # If we find the entry in the LSDB
            current_cost = None if each_fwd_entry[COST] is None else each_fwd_entry[COST]
            incoming_cost = None if dest_cost_from_the_lsv_node is None else (int(dest_cost_from_the_lsv_node) + 1) # As the LSV is from the immediate neighbour

            if each_fwd_entry[DESTINATION] == dest_ip_port:
                # Special case, if the destination in the received LSV is actually adjacent for the current node
                # The cost should be 1 for the destination and should not be updated
                if dest_ip_port in my_adjacent_nodes:
                    continue
                # If the node sending the LSV is my immediate node
                if source_of_lsv in my_adjacent_nodes:
                    # Case 1: We are unable to reach this particular destination from this adjacent node
                    if incoming_cost is None and current_cost is not None:
                        # Case 1.a: The next hop was this same node
                        #       Update the next hop and set the node as unreachable
                        # LOG.critical("The incoming cost is None, but the current was not, Setting to NONE!")
                        if each_fwd_entry[NEXT_HOP] == source_of_lsv:
                            each_fwd_entry[COST] = None
                            each_fwd_entry[NEXT_HOP] = None
                            route_topology[each_fwd_entry[DESTINATION]] = []
                            topo_updated = True
                        # Case 1.b: The next hop was NOT this node
                        #       Do not update anything, we might be able to reach through some other node
                        #       If that node also cannot reach, it will update with the above case
                        else:
                            pass
                    # Case 2: The node was previously unreachable, but we got a path where the node is now reachable
                    elif incoming_cost is not None and current_cost is None:
                        # Case 2.a: Since the current cost is None, the next hop is also not there -- just update to the new value
                        # Use the new path that we received
                        each_fwd_entry[NEXT_HOP] = source_of_lsv
                        each_fwd_entry[COST] = incoming_cost
                        route_topology[each_fwd_entry[DESTINATION]] = dest_path_from_the_lsv_node
                        # And append the next hop to it.
                        route_topology[each_fwd_entry[DESTINATION]].append(source_of_lsv)
                    # Case 3: The node was reachable and still is from this node, need to check the cost
                    elif incoming_cost is not None and current_cost is not None:
                        # Case 3.a: The LSV source advertizes a lesser cost to the node
                        if incoming_cost < current_cost:
                            # Update the next hop, path and the cost
                            each_fwd_entry[NEXT_HOP] = source_of_lsv
                            each_fwd_entry[COST] = incoming_cost
                            route_topology[each_fwd_entry[DESTINATION]] = dest_path_from_the_lsv_node
                            route_topology[each_fwd_entry[DESTINATION]].append(source_of_lsv)
                        else:
                            # Case 3.b: The LSV source has more cost to the node
                            # In this case, we will send the new path (with lower cost) back to that node, which will done with the LSVR 
                            pass
                    # Case 4: If the dest was unreachable then and still is, skip
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


def readtopology(topology_file, self_ip, self_name, self_host, my_adjacent_nodes, full_network_topology, port):
    with open(topology_file, "r") as topo_file:
 
        for each_adjacent_topology in topo_file:
            each_adjacent_topology = each_adjacent_topology.rstrip('\n')
            if each_adjacent_topology != '\n':
                # Check if we are reading the adjacent nodes for the current node
                current_topology = each_adjacent_topology.split(" ")
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
    print("ROUTE TOPOLOGY IS : {}", route_topology)
    # print("\n\n The INITIAL forwarding table is as follows: ")
    print(f"Routing table is {fwd_table}")
    print_fwd_table(fwd_table)
    if DEBUG_PRINT:
        print("\nThe adjacent nodes for me are: ")
        for adj_node in my_adjacent_nodes:
            print(f"{adj_node[0]}:{adj_node[1]}")
    return route_topology, fwd_table, helloTimestamps, largestSeqNoPerNode, TTL
            
            
if __name__ == "__main__":
    # 1. Parse arguments
    parser = argparse.ArgumentParser(description="Emulates network for UDP")
    parser.add_argument("-p", "--port", dest="port", type=int, required=True, help="Port on which the emulator runs")
    parser.add_argument("-f", "--filename", dest="topology_file", type=str, required=True, help="File containing information about the static forwarding table")

    args = parser.parse_args()

    # 3. Read the topology and get the immediately adjacent nodes of current node
    # self_name = socket.gethostname()
    self_name = "localhost"
    # self_ip = socket.gethostbyname(self_name)    
    self_ip = socket.gethostbyname("127.0.0.1")
    my_adjacent_nodes = []
    self_host = tuple([self_ip, int(args.port)])
    full_network_topology = set() # List of all nodes in the current network
    
    route_topology, fwd_table, helloTimestamps, largestSeqNoPerNode, TTL = readtopology(args.topology_file,self_ip, self_name, self_host, my_adjacent_nodes, full_network_topology, args.port)
    
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
                if DEBUG_PRINT == 1:
                    print(f"Received HELLO FROM MY NEIGHBOUR {source[0]}:{source[1]}")
                # If the neighbour was considered down for some time, update the cost and the next hop for that node
                if helloTimestamps.get(source, 0) == 0 and source in my_adjacent_nodes:
                    for fwd_entry in fwd_table:
                        if fwd_entry[DESTINATION] == source:
                            fwd_entry[COST] = 1
                            route_topology[source] = [source]
                            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip, args.port)
                            print("Topology changed. Node {} is now reachable. Current FWD table".format(source))
                            print_fwd_table(fwd_table)
                            break
                helloTimestamps[source] = current_time
            # Case C: If a Link State message or RouteTrace or RouteTraceReply
            elif packet_type in [PACKET_TYPE_LINK_STATE]:
                #   Check the LSN and check if newer than what we had. Discard if not            
                if largestSeqNoPerNode.get(source, 0) < seq_no:
                    # The sequence number is valid
                    largestSeqNoPerNode[source] = seq_no
                    # TODO Topology change == update the route topology and fwd_table
                    received_lsv = decode_link_state_vector(inner_data)
                    if received_lsv is None:
                        pass
                    else:
                        if DEBUG_PRINT == 1:
                            print(f"The source {source}     SENT LSV -> {received_lsv}\n\n")
                            print(largestSeqNoPerNode)
                        topology_changed = False
                        if inner_len >= 1: # Now we will decrement the TTL of the packet
                            topology_changed = build_ForwardTable(fwd_table, received_lsv, source, my_adjacent_nodes, route_topology)
                            if topology_changed:
                                send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip, args.port)
                                #   Call forwardpacket to flood to neighbours
                                print("topology_changed: The route topo is {}".format(route_topology))
                                forwardpacket(data, my_adjacent_nodes, fwd_table, self_ip, args.port)
                        print_fwd_table(fwd_table)
                        # print("ROUTE TOPOLOGY NOW IS ::: {}".format(route_topology))
                else:
                    pass
            elif packet_type in [PACKET_TYPE_ROUTE_TRACE, PACKET_TYPE_ROUTE_TRACE_REPLY]:
                forwardpacket(data, my_adjacent_nodes,fwd_table,self_ip,args.port)
                pass
            pass

        # 3. Send the HelloMessage if timedelta has passed
        if current_time - myLastHello >= HELLO_MESSAGE_DELTA:
            for adj_node in my_adjacent_nodes:
                send_hello_message(self_ip, args.port, adj_node[0], adj_node[1])
            myLastHello = current_time

        # 4. Check the neighbors and update the fwd table as required
        deletion_entries = []
        node_state_changed = False
        for neighbour, lastHelloTS in helloTimestamps.items():
            if current_time - lastHelloTS > NO_MESSAGE_TOLERANCE*HELLO_MESSAGE_DELTA:
                aNodeWentDown = True
                helloTimestamps[neighbour] = 0
                for fwd_entry in fwd_table:
                    if (fwd_entry[NEXT_HOP] == neighbour):
                        # If it is an immediate neighbour, do not delete the next hop
                        # as the next hop will be that node only
                        fwd_entry[COST] = None
                        deletion_entries.append(fwd_entry)
                        if fwd_entry[DESTINATION] in my_adjacent_nodes:
                            node_state_changed = True
                            print("Removed the entries {} as no HELLO received from them. Updated forwarding table:".format(fwd_entry))
                            continue
                        else:
                            fwd_entry[NEXT_HOP] = None
                            node_state_changed = True
                            print("Removed the entries {} as no HELLO received from them. Updated forwarding table:".format(fwd_entry))
                            continue
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
            print_fwd_table(fwd_table)
        if node_state_changed:
            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip, args.port)

        # 5. Send the newest LinkStateMessage to all neighbors if time has passed
        if current_time - myLastLSM > LINK_STATE_MSG_TIMEOUT:
            if DEBUG_PRINT == 1:
                print("Timeout occured for LSM. Resending the latest LSV")
            send_link_state_message(my_adjacent_nodes, fwd_table, route_topology, TTL, self_ip,args.port)
        continue

