import socket
import struct
import os
from io import BlockingIOError
import time
import argparse
import ipaddress

"""Receives request from the Requester for the filename (from which data is to be sent)"""
def receive_request(UDP_IP, UDP_PORT):
	sock = None
	try:
		sock = socket.socket(socket.AF_INET, # Internet
							socket.SOCK_DGRAM) # UDP

		# print("Sender waiting on IP address {} @ port {}".format(UDP_IP, UDP_PORT))
		sock.bind(('0.0.0.0', UDP_PORT))
		# print("Waiting on IP {} at port {}".format(UDP_IP, UDP_PORT))

		while True:
			data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
			outer_header = data[0:17]
			outer_header_up = struct.unpack("<cIhIhI", outer_header)
			packet_type = data[17:18].decode('utf-8')
			header = data[18:26]
			header = struct.unpack('<II', header)
			sequence_number_network = header[0]
			sequence_number = socket.ntohl(sequence_number_network)
			#packet_length = struct.unpack('!I', data[5:9])[0]
			packet_length = header[1]

			print("Packet type:     %s"% packet_type)
			print("Sequence no.:    %d" % sequence_number)
			filename = data[26:].decode('utf-8')
			print("Payload:         %s "% filename)
			print("\n")

			sock.close()
			return packet_type, filename, addr, packet_length
	
	except Exception as ex:
		raise ex


def Receive_ACK(timeout, UDP_PORT, window):
	start_time = time.time()
	sock_receive = socket.socket(socket.AF_INET, # Internet
			socket.SOCK_DGRAM)
	
	sock_receive.setblocking(0)
	sock_receive.bind(('0.0.0.0', UDP_PORT))

	while time.time() - start_time < timeout:
		try:
			# TODO Extract data from the new header and then old header (check receive_request) - Done
			data_ack, addr = sock_receive.recvfrom(1024) # buffer size is 1024 bytes
			outer_header = data_ack[0:17]
			outer_header_up = struct.unpack("<cIhIhI", outer_header)
			packet_type = data_ack[17:18].decode('utf-8')
		
			print(f"This is the packet type {packet_type}")
		
			if packet_type == 'A':
				header_ack = data_ack[18:26]
				header_ack = struct.unpack('II', header_ack)
				sequence_number_network_ack = header_ack[0]
				sequence_number_ack = socket.ntohl(sequence_number_network_ack)

			if sequence_number_ack in window:
				print(f"Received ACK for sequence_number : {sequence_number_ack}")
				window.pop(sequence_number_ack)
		
		except BlockingIOError as bie:
			continue
	
	return window

def packet_retransmit(window,retransmission_count,packet_type,payload_length,requester_addr,requestor_wait_port,sock,rate,total_transmissions, emulator_host, emulator_port,priority):

	key_copy = tuple(window.keys())
	for seq_no in key_copy:
		retransmission_count[seq_no] += 1
		if retransmission_count[seq_no] < 6:

			header = create_header(packet_type, seq_no, payload_length)
			# TODO Create and add new header in front of old header
			inner_payload = header + window[seq_no].encode("utf-8")
					# TODO Remove the hardcoded port
			outer_header =  struct.pack("<cIhIhI", "1".encode('utf-8'), int(ipaddress.ip_address(socket.gethostbyname(socket.gethostname()))), 5000, int(ipaddress.ip_address(requester_addr)), requestor_wait_port, len(inner_payload))

			#sock.sendto((outer_header + inner_payload),
			#		(emulator_host, emulator_port))
			
			sock.sendto((outer_header + inner_payload),
					(requester_addr, requestor_wait_port))

			print(f"Retransmitting Packet...for sequence number {seq_no} and count is {retransmission_count[seq_no]}")
			
			
			total_transmissions += 1
			flag = 0
			time.sleep(1/rate)
		else:
			print(f"Gave up on packet with sequence number {seq_no} after {5} retransmits.")
			window.pop(seq_no)
			
	return window


def create_header(packet_type, sequence_number, payload_length):
	sequence_number_network = socket.htonl(sequence_number)
	header = str(packet_type).encode("utf-8") + struct.pack('II', sequence_number_network, payload_length)
	return header


def send_packets(packet_type, requester_addr, requestor_wait_port, sequence_number, payload_length, rate, message, timeout, window_size, UDP_PORT, emulator_host, emulator_port,priority):
	try:
		max_retransmits = 5
		window = {}
		total_transmissions = 0
		retransmission_count = {}
		buffer = []
		sequence_number = 1

		if packet_type == "D" and message != "":
			
			chunks = [message[i:i + payload_length] for i in range(0, len(message), payload_length)]
			k = 0
			while (k<len(chunks)):
				sock = socket.socket(socket.AF_INET, # Internet
		socket.SOCK_DGRAM) # UDP

		# sock.bind((requester_addr, 5000))
				for n in chunks[k:k+window_size]:
					header = create_header(packet_type, sequence_number, payload_length)
					inner_payload = header
					# TODO Remove the hardcoded port
					outer_header =  struct.pack("<cIhIhI", "1".encode('utf-8'), int(ipaddress.ip_address(socket.gethostbyname(socket.gethostname()))), 5000, int(ipaddress.ip_address(requester_addr)), requestor_wait_port, len(inner_payload))

					

					#sock.sendto((outer_header + inner_payload),(emulator_host, emulator_port))

					sock.sendto((outer_header + inner_payload + n.encode("utf-8")),
					(requester_addr, requestor_wait_port))

					print(f"Sending Packet... with sequence number : {sequence_number}")

					current_time = time.time()
					milliseconds = int((current_time - int(current_time)) * 1000)

					print("DATA Packet")
					print(f"Send Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
					print(f"Requester Addr:     {requester_addr}:{requestor_wait_port}")
					print(f"Seq No:             {sequence_number}")
					print(f"Length:             {len(n)}")
					print(f"Payload:            {n[:4]}")
					print("\n")
					
					window[sequence_number] = n

					sequence_number += 1
					
					total_transmissions += 1

					time.sleep(1/rate)
				
				window = Receive_ACK(timeout,UDP_PORT,window)

				if (bool(window)) == True:
					print("Did not receive ACK")
					for seq_no in window:
						retransmission_count[seq_no] = 0
				
				while bool(window) == True:
					window = packet_retransmit(window,retransmission_count,packet_type,payload_length,requester_addr,requestor_wait_port,sock,rate,total_transmissions, emulator_host, emulator_port,priority)
					if bool(window) == False:
						break
					window = Receive_ACK(timeout,UDP_PORT,window)

		
				k = k + window_size

						
		end_header = create_header('E', sequence_number, 0)
		#sock.sendto(end_header + str(0).encode("utf-8"), (emulator_host, emulator_port))

		end_outer_header =  struct.pack("<cIhIhI", "1".encode('utf-8'), int(ipaddress.ip_address(socket.gethostbyname(socket.gethostname()))), 5000, int(ipaddress.ip_address(requester_addr)), requestor_wait_port, 0)
		sock.sendto((end_outer_header + end_header),
					(requester_addr, requestor_wait_port))



		current_time = time.time()
		milliseconds = int((current_time - int(current_time)) * 1000)
		print("\nEND Packet")
		print(f"Send Time:          {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
		print(f"Requester Addr:     {requester_addr}:{requestor_wait_port}")
		print(f"Seq No:             {sequence_number}")
		print(f"Length:             {0}")
		print(f"Payload:            {0}")
		print("\n")
	except Exception as ex:
		raise ex


def main(sender_wait_port, requestor_port, packet_rate, start_seq_no, payload_length, timeout, emulator_host, emulator_port, priority):
	packet_type, filename, client_address, window_size = receive_request(socket.gethostbyname(socket.gethostname()), sender_wait_port)
	print("Requestor waits on IP: %s" % client_address[0])
	print("Sender waiting on port: %s \n" % sender_wait_port)
	if packet_type == 'R':
		if os.path.exists(filename):
			with open(filename, "rb") as fd:
				message = fd.read().decode("utf-8")
				# Client address is combination of IP Address and port
				send_packets('D', client_address[0], requestor_port, start_seq_no, payload_length, packet_rate, str(message), timeout, window_size, sender_wait_port, emulator_host, emulator_port,priority)
		else:
			print("File with name {} does not exist. Ending the connection.\n".format(filename))
			send_packets('E', client_address[0], requestor_port, start_seq_no, payload_length, packet_rate, "", timeout, window_size,sender_wait_port, emulator_host, emulator_port, priority)


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Sends chunks of a file to the requester")
	parser.add_argument("-p", "--port", dest='port', type=int, required=True, help="Port number on which the sender waits for request")
	parser.add_argument("-r", "--rate", dest='rate', type=int, required=True, help="Rate of packets per sec to send")
	parser.add_argument("-g", "--req-port", dest="requestor_port", type=int, required=True, help="Port number on which the requestor is waiting")
	parser.add_argument("-q", "--seq-no", dest="start_seq_no", type=int, required=True, help="Initial sequence number of the package exchange")
	parser.add_argument("-l", "--length", dest="payload_length", type=int, required=True, help="Length of the payload in the packets (in bytes)")
	parser.add_argument("-t", "--timeout", dest="timeout", type=float, required=True, help="Timeout to receive ACK")
	parser.add_argument("-f", dest="emulator_host_name", type=str, required=True, help="Hostname of the emulator")
	parser.add_argument("-e", dest="emulator_port", type=int, required=True, help="Port of the emulator")
	parser.add_argument("-i", dest="priority", type=int, required=True, help="Priority of the packets")

	args = parser.parse_args()
	for port_numbers in [args.port, args.requestor_port]:
		if port_numbers not in range(2050, 65536):
			raise Exception("Port number should be in the range 2050 to 65535. Passed: {}".format(port_numbers))
	main(args.port, args.requestor_port, args.rate, args.start_seq_no, args.payload_length, args.timeout, args.emulator_host_name, args.emulator_port,args.priority)




