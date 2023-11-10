import socket
import struct
import os
import time
import datetime
import math
import argparse
import ipaddress
from utils_640 import *
import threading
from threading import Lock

THREADS = []
received_data = {}
received_data_lock = Lock()

def send_request(packet_type,Sender_IP, sender_port, filename, emulator_name, emulator_port,priority,window, waiting_port):
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		seq_no = socket.htonl(0)
		request_inner_header = str(packet_type).encode("utf-8") + struct.pack('II', seq_no, window)
		#request_outer_header =  struct.pack("<cIhIhI", "1".encode('utf-8'), int(ipaddress.ip_address(socket.gethostbyname(socket.gethostname()))), waiting_port, int(ipaddress.ip_address(Sender_IP)), sender_port, int(len(request_inner_header)))
		request_outer_header =  struct.pack("<cIhIhI",
									  "1".encode('utf-8'),
									  int(ipaddress.ip_address(socket.gethostbyname(socket.gethostname()))), waiting_port,
									  int(ipaddress.ip_address(Sender_IP)),
									  sender_port,
									  int(len(request_inner_header)))
		sock.sendto(request_outer_header + request_inner_header + bytes(filename, 'utf-8'), (emulator_name,emulator_port))
		print(f"Request sent to the sender !!")
		sock.close()
	except Exception as ex:
		raise ex


def send_ack(Sender_IP, sender_port, emulator_name, emulator_port,priority, waiting_port):
	global received_data, received_data_lock
	end_received = False
	sock = None
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		while True:
			key_copy = tuple(received_data.keys())
			for check_tuple in sorted(key_copy):
				if not (check_tuple[0] == Sender_IP and check_tuple[1] == sender_port):
					return
				packet_type = received_data[check_tuple][17:18].decode('utf-8')
				request_inner_header = 'A'.encode("utf-8") + struct.pack('II', check_tuple[2], 0)
				request_outer_header =  struct.pack("<cIhIhI",
											str(priority).encode('utf-8'),
											int(ipaddress.ip_address(socket.gethostbyname(socket.gethostname()))), waiting_port,
											int(ipaddress.ip_address(Sender_IP)), sender_port,
											int(len(request_inner_header))
										)
				
				sock.sendto(request_outer_header + request_inner_header + '1'.encode('utf-8'), (emulator_name,emulator_port))
				
				print(f"ACK sent to the sender for sequence number : {check_tuple}")
				received_data_lock.acquire()
				if check_tuple in received_data:
					received_data.pop(check_tuple)
				received_data_lock.release()
				
				if packet_type == 'E':
					end_received = True
			if end_received:
				# print("SAHIL!! THE DATA END RECEIVED!!!!! \n Returning from the thread")
				return
	except Exception as ex:
		raise ex
	finally:
		if sock:
			sock.close()


def receive_data(UDP_IP, UDP_PORT, filename,Sender_IP, sender_port,window, emulator_name, emulator_port):
	try:
		sock = socket.socket(socket.AF_INET, # Internet
							socket.SOCK_DGRAM) # UDP
		# print("Requster waiting on IP {} @ port {}".format(UDP_IP, UDP_PORT))
		sock.setblocking(0)
		global received_data, received_data_lock
		sock.bind(('0.0.0.0', UDP_PORT))
		start_time = None
		count = 0
		length_of_payload = 0
		buffer = {}
		timeout = 1
		data = []
		while True:

			try:

				data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
				outer_header = data[0:17]
				outer_header_up = struct.unpack("<cIhIhI", outer_header)
				actual_sender_ip = str(ipaddress.ip_address(outer_header_up[3]))
				actual_sender_port = outer_header_up[4]
				packet_type = data[17:18].decode('utf-8')
				header = data[18:26]
				header = struct.unpack('II', header)
				sequence_number_network = header[0]
				sequence_number = socket.ntohl(sequence_number_network)
				#packet_length = struct.unpack('!I', data[5:9])[0]
				packet_length = header[1]
				count = count + 1
				length_of_payload = length_of_payload + packet_length

				payload = data[26:].decode('utf-8')
				
				#payload = str(data[9:])
				print(f"Packet Type:    {packet_type}")
				print(f"Recv Time:      {str(datetime.datetime.now())}")
				print(f"Sender Addr:    {addr[0]}:{addr[1]}")
				print(f"Seq No:         {sequence_number}")
				print(f"Length:         {packet_length}")
				print(f"Payload:        {data[26:(26+4)].decode('utf-8')}")
				
				received_data_lock.acquire()
				key_tuple = (actual_sender_ip, actual_sender_port, sequence_number)
				if packet_type == 'D':
					if bool(received_data) == False:
						received_data[key_tuple] = data
						buffer[key_tuple] = data
						
						with open(filename, "a") as copied_file:
							copied_file.write(payload)
						print("\n")
					elif key_tuple in buffer:
						received_data[key_tuple] = data
					else:
						received_data[key_tuple] = data
						buffer[key_tuple] = data
						
						with open(filename, "a") as copied_file:
							copied_file.write(payload)
						print("\n")
				received_data_lock.release()
				if packet_type == 'E':
					end_time = time.time()
					if start_time is None:
						# case where the file does not exist on the sender
						start_time = end_time
					duration = end_time - start_time
					break
			except BlockingIOError as bie:
				pass

		print("\n\n")
		print("="*60)
		print("Summary of Sender")
		print(f"Sender addr:                {addr[0]}:{addr[1]}")
		print(f"Total Data Packets:         {count - 1}")
		print(f"Total Data Bytes:           {length_of_payload}")
		print(f"Average packets/second:     {math.ceil((count - 1) / float(duration)) if duration != 0 else 1}")
		print(f"Total Duration of the test: {round(duration*1000, 2)} ms")
		print("="*60)
		print("\n\n")
		sock.close()
	except Exception as ex:
		raise ex


def main(waiting_port, file_to_request, window, emulator_host, emulator_port):
	tracker_data = []
	threads = []
	if os.path.exists("tracker.txt"):
		with open("tracker.txt", "r") as tracker_file:
			trackings = tracker_file.readlines()
			for each_line in trackings:
				filename, chunk_id, hostname, req_port = each_line.split(" ")
				# Filter the tracker file based on the filename requested
				if filename == file_to_request:
					tracker_data.append((filename, int(chunk_id), hostname, int(req_port)))
		tracker_data.sort(key=lambda x: (x[0], x[1]))
		for filtered_host_info in tracker_data:
			# print(f"Requesting file: {filtered_host_info[0]} Chunk ID: {filtered_host_info[1]} from Host {filtered_host_info[2]} {(socket.gethostbyname(filtered_host_info[2]))} @ port {filtered_host_info[3]}")
			send_thread = threading.Thread(target=send_ack, daemon=True, args=(socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3], emulator_host, emulator_port, 1, waiting_port))
			send_thread.start()
			threads.append(send_thread)
			send_request('R',socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3], file_to_request, emulator_host, emulator_port, 1, window, waiting_port)
			receive_data(socket.gethostbyname(socket.gethostname()), waiting_port, file_to_request,socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3],window, emulator_host, emulator_port)
	else:
		raise Exception("Tracker file does not exist.")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Receive chunks of a file from different senders")
	parser.add_argument("-p", "--port", dest='port', type=int, required=True, help="Port number on which the requester waits for packets")
	parser.add_argument("-o", "--file-option", dest='file_option', type=str, required=True, help="File name to get the data for")
	parser.add_argument("-w", "--window_size", dest='window', type=int, required=True, help="Window size to request data")
	parser.add_argument("-f", dest="emulator_host_name", type=str, required=True, help="Hostname of the emulator")
	parser.add_argument("-e", dest="emulator_port", type=int, required=True, help="Port of the emulator")
	args = parser.parse_args()
	if args.port not in range(2050, 65536):
		raise Exception("Port number should be in the range 2050 to 65535. Passed: {}".format(args.port))
	main(args.port, args.file_option, args.window, args.emulator_host_name, args.emulator_port)

