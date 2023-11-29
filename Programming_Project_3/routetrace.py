import socket
import struct
import os
from io import BlockingIOError
import time
from utils_640 import *
import argparse
import ipaddress
from threading import Thread, Lock

def create_header(src_ip_addr, src_port, dest_ip_addr, dest_port, TTL):
	src_ip_int = ipaddress.v4_int_to_packed(src_ip_addr)
	dst_ip_int = ipaddress.v4_int_to_packed(dest_ip_addr)
	header = struct.pack("IhIhI", src_ip_int, src_port, dst_ip_int, dest_port, TTL)
	packet = str('T').encode("utf-8") + header
	return header


def main(route_port, src_hostname, src_port, dest_hostname, dest_port, debug):
	sock = socket.socket(socket.AF_INET, # Internet
				socket.SOCK_DGRAM) # UDP
	TTL = 0
	packet = create_header(src_hostname,src_port,dest_hostname,dest_port,TTL)
	sock.sendto(packet, (src_hostname, src_port))
	
	current_time = time.time()
	milliseconds = int((current_time - int(current_time)) * 1000)
	
	if debug:
		print("\nRoute Packet")
		print(f"Send Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
		print(f"Sender Addr:     {str(ipaddress.ip_address(src_hostname))}:{src_port}")
		print(f"Destination Addr:     {str(ipaddress.ip_address(dest_hostname))}:{dest_port}")
		print(f"TTL :             {TTL}")
		print("\n")
		
	sock_receive = socket.socket(socket.AF_INET, # Internet
			socket.SOCK_DGRAM)
	sock_receive.bind(('0.0.0.0', route_port))
	
	while True:
		data, addr = sock_receive.recvfrom(1024)
		packet_type = data[0]
		header = struct.unpack("<IhIhI", data[1:])
		s_hostname, s_port, d_hostname, d_port = header
		
		current_time = time.time()
		milliseconds = int((current_time - int(current_time)) * 1000)
	
		if debug:
			print("\nReply Packet")
			print(f"Send Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
			print(f"Sender Addr:     {str(ipaddress.ip_address(s_hostname))}:{s_port}")
			print(f"Destination Addr:     {str(ipaddress.ip_address(d_hostname))}:{d_hostname}")
			print(f"TTL :             {TTL}")
			print("\n")
		
		if packet_type == 'Y':
			if d_hostname == dest_hostname and d_port == dest_port:
				break
			else:
				TTL += 1
				create_header(src_hostname,src_port,dest_hostname,dest_port,TTL)
				sock.sendto(packet, (src_hostname, src_port))
				if debug:
					print("\nRoute Packet")
					print(f"Send Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
					print(f"Sender Addr:     {str(ipaddress.ip_address(src_hostname))}:{src_port}")
					print(f"Destination Addr:     {str(ipaddress.ip_address(dest_hostname))}:{dest_port}")
					print(f"TTL :             {TTL}")
					print("\n")
		
		
if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Sends chunks of a file to the requester")
	parser.add_argument("-a", "--route_trace_port", dest='route_port', type=int, required=True, help="Port number on which the route trace waits for packets")
	parser.add_argument("-b", "--src_hostname", dest='src_hostname', type=int, required=True, help="Source hostname")
	parser.add_argument("-c", "--src_port", dest="src_port", type=int, required=True, help="Port number on which the source is waiting")
	parser.add_argument("-d", "--dest_hostname", dest="dest_hostname", type=int, required=True, help="Destination hostname")
	parser.add_argument("-e", "--des_port", dest="dest_port", type=int, required=True, help="Port number on which destination is waiting")
	parser.add_argument("-t", "--debug", dest="debug", type=float, default = 0, required=False, help="To enable or disable the printing")
	

	args = parser.parse_args()
	for port_numbers in [args.port, args.requestor_port]:
		if port_numbers not in range(2050, 65536):
			raise Exception("Port number should be in the range 2050 to 65535. Passed: {}".format(port_numbers))
	main(args.route_port, args.src_hostname, args.src_port, args.dest_hostname, args.dest_port, args.debug)

