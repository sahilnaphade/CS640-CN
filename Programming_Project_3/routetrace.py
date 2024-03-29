import socket
import struct
import os
from io import BlockingIOError
import time
from utils import *
import argparse
import ipaddress
from threading import Thread, Lock

def create_header(src_ip_addr, src_port, dest_ip_addr, dest_port, TTL):
	src_ip_int = ipaddress.v4_int_to_packed(src_ip_addr)
	dst_ip_int = ipaddress.v4_int_to_packed(dest_ip_addr)
	header = struct.pack("IhIhI", src_ip_int, src_port, dst_ip_int, dest_port, TTL)
	packet = str('T').encode("utf-8") + header
	return header


def print_fwd_table(fwd_table):
    # print(['Hop No ', 'IP', '  Port'])
    # for entry in fwd_table:
    #     print(str(entry[0]) + " " + str(entry[1]) + " " + str(entry[2]) , "\n")
    # print("\n\n")
	
	print ("{:<12} {:<14} {:<1}".format('Hop #','IP','Port'))
	print(32*"#")
	
	for k, v in fwd_table.items():
		lang, perc = v
		print ("{:<9} {:<17} {:<7}".format(k, lang, perc))
	print("\n")

def debugprint(route_trace, TTL, src_hostname, src_port, dest_port, dest_hostname, s_hostname, s_port, d_hostname, d_port, received_TTL):
	current_time = time.time()
	milliseconds = int((current_time - int(current_time)) * 1000)
	if route_trace:
		print("\nRoute Packet")
		print(f"Send Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
		print(f"Sender Addr:     {str(ipaddress.ip_address(src_hostname))}:{src_port}")
		print(f"Destination Addr:     {str(ipaddress.ip_address(dest_hostname))}:{dest_port}")
		print(f"TTL :             {TTL}")
		print("\n")
	
	else:
		print("\nReply Packet")
		print(f"Send Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
		print(f"Sender Addr:     {str(ipaddress.ip_address(s_hostname))}:{s_port}")
		print(f"Destination Addr:     {str(ipaddress.ip_address(d_hostname))}:{d_port}")
		print(f"TTL :             {received_TTL}")
		print("\n")
		
def main(route_port, src_hostname, src_port, dest_hostname, dest_port, debug):
	sock = socket.socket(socket.AF_INET, # Internet
				socket.SOCK_DGRAM) # UDP
	TTL = 0
	payload = str((socket.gethostbyname(socket.gethostname()))+ ":" + str(route_port))
	inner_payload = inner_payload_encapsulate('T', 0, payload,TTL)
	packet = outer_payload_encapsulate(socket.gethostbyname(socket.gethostname()),route_port,socket.gethostbyname(dest_hostname),dest_port,inner_payload)
	sock.sendto(packet, (socket.gethostbyname(src_hostname), src_port))
	hop_table = {}
	current_time = time.time()
	milliseconds = int((current_time - int(current_time)) * 1000)
	
	# if debug:
		# debugprint(1, TTL, src_hostname, src_port, dest_port, dest_hostname, s_hostname, s_port, d_hostname, d_port, received_TTL)
		
	sock_receive = socket.socket(socket.AF_INET, # Internet
			socket.SOCK_DGRAM)
	sock_receive.bind(('0.0.0.0', route_port))
	hop = 0
	while True:
		data, addr = sock_receive.recvfrom(1024)
		priority, s_hostname, s_port, d_hostname, d_port, length, packet_type, received_TTL, inner_length, data = outer_payload_decapsulate(data)
		
		if debug:
			debugprint(0, TTL, s_hostname, s_port, dest_port, dest_hostname, s_hostname, s_port, d_hostname, d_port, received_TTL)
			
		if packet_type == 'Y':
			if "UNREACHABLE" in data:
				print(f"Node {s_hostname}:{s_port} informed that the destination {d_hostname}:{d_port} is currently unreachable from it. Exiting the routetrace...")
				exit(0)
			hop += 1
			hop_table[hop] = ([s_hostname,s_port])
			
			if ((s_hostname == dest_hostname) and (s_port == dest_port)):
				print("\nReceived Packet from my required Destination !!! \n")
				break
			else:
				TTL += 1
				inner_payload = inner_payload_encapsulate('T', 0, payload, TTL)
				packet = outer_payload_encapsulate(socket.gethostbyname(socket.gethostname()),route_port,socket.gethostbyname(dest_hostname),dest_port,inner_payload)
				sock.sendto(packet, (src_hostname, src_port))
				if debug:
					debugprint(1, TTL, src_hostname, src_port, dest_port, dest_hostname, s_hostname, s_port, d_hostname, d_port, received_TTL)
					
	print(f"The hopping table is :\n")
	print_fwd_table(hop_table)
		
		
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Sends chunks of a file to the requester")
	parser.add_argument("-a", "--route_trace_port", dest='route_port', type=int, required=True, help="Port number on which the route trace waits for packets")
	parser.add_argument("-b", "--src_hostname", dest='src_hostname', type=str, required=True, help="Source hostname")
	parser.add_argument("-c", "--src_port", dest="src_port", type=int, required=True, help="Port number on which the source is waiting")
	parser.add_argument("-d", "--dest_hostname", dest="dest_hostname", type=str, required=True, help="Destination hostname")
	parser.add_argument("-e", "--des_port", dest="dest_port", type=int, required=True, help="Port number on which destination is waiting")
	parser.add_argument("-t", "--debug", dest="debug", type=float, default = 0, required=False, help="To enable or disable the printing")
	

	args = parser.parse_args()
	for port_numbers in [args.route_port]:
		if port_numbers not in range(2050, 65536):
			raise Exception("Port number should be in the range 2050 to 65535. Passed: {}".format(port_numbers))
	main(args.route_port, args.src_hostname, args.src_port, args.dest_hostname, args.dest_port, args.debug)

