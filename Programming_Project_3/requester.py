import socket
import struct
import os
from time import time
from copy import deepcopy
import math
import argparse
import ipaddress
from utils import *
from threading import Lock, Thread

THREADS = []
received_data = {}
received_data_lock = Lock()
sender_start_times = {}

myLSN = 1
myLastHello = 0 # Timestamp of last hello message
HELLO_MESSAGE_DELTA = 500


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

def send_hello_message(src_ip, src_port, dest_ip, dest_port):
	global myLSN, myLastHello
	send_sock = None
	inner_pack = inner_payload_encapsulate(PACKET_TYPE_HELLO, myLSN, "", 0)
	final_pack = outer_payload_encapsulate(src_ip, src_port, dest_ip, dest_port, inner_pack)
	
	while True:
		current_time = round(time() * 1000)
		if current_time - myLastHello >= HELLO_MESSAGE_DELTA:
			try:
				send_sock = socket.socket(socket.AF_INET, socket.AF_INET)
				send_sock.sendto(final_pack, (dest_ip, dest_port))
				myLastHello = round(time() * 1000)
				print(f"Sent hello to {dest_ip}:{dest_port} at time {myLastHello}")
			except Exception as ex:
				raise ex
			finally:
				if send_sock is not None:
					send_sock.close()
				myLSN += 1
			pass
		
def receive_data(UDP_IP, UDP_PORT, filename, tracker_data, window, emulator_name, emulator_port):
	sock = send_sock = None
	try:
		sock = socket.socket(socket.AF_INET, # Internet
							socket.SOCK_DGRAM) # UDP
		send_sock = socket.socket(socket.AF_INET,
							socket.SOCK_DGRAM)
		# print("Requster waiting on IP {} @ port {}".format(UDP_IP, UDP_PORT))
		sock.setblocking(0)
		number_of_trackers = len(tracker_data)
		global received_data, received_data_lock, sender_start_times
		sock.bind(('0.0.0.0', UDP_PORT))
		start_time = None
		count = 0
		length_of_payload = 0
		buffer = {}
		timeout = 1
		data = []
		payload_data = {}
		while True:

			try:

				data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
				outer_header = data[0:17]
				outer_header_up = struct.unpack("<cIhIhI", outer_header)
				
				actual_sender_ip = str(ipaddress.ip_address(outer_header_up[1]))
				actual_sender_port = outer_header_up[2]
				
				if str(ipaddress.ip_address(outer_header_up[3])) == str(socket.gethostbyname(socket.gethostname())) and outer_header_up[4] == UDP_PORT :
					#start_time = time.time()
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
					# print(f"Packet Type:    {packet_type}")
					# print(f"Recv Time:      {str(datetime.datetime.now())}")
					# print(f"Sender Addr:    {actual_sender_ip}:{sender_port}")
					# print(f"Seq No:         {sequence_number}")
					# print(f"Length:         {packet_length}")
					# print(f"Payload:        {data[26:(26+4)].decode('utf-8')}")
					
					received_data_lock.acquire()
					key_tuple = (actual_sender_ip, actual_sender_port, sequence_number)
					sender_tuple = (actual_sender_ip, actual_sender_port)
					if sender_tuple not in payload_data:
						payload_data[sender_tuple] = {}
					if sender_tuple not in sender_start_times:
						sender_start_times[sender_tuple] = time()
					if packet_type == 'D':
						if bool(received_data) == False:
							received_data[key_tuple] = data
							buffer[key_tuple] = data
							payload_data[sender_tuple][sequence_number] = payload
			
						elif key_tuple in buffer:
							received_data[key_tuple] = data
						else:
							received_data[key_tuple] = data
							buffer[key_tuple] = data
							payload_data[sender_tuple][sequence_number] = payload
						# Send ack for the packet
						request_inner_header = 'A'.encode("utf-8") + struct.pack('II', sequence_number, 0)
						request_outer_header =  struct.pack("<cIhIhI",
											str(1).encode('utf-8'),
											int(ipaddress.ip_address(socket.gethostbyname(socket.gethostname()))),
											UDP_PORT,
											int(ipaddress.ip_address(actual_sender_ip)),
											actual_sender_port,
											int(len(request_inner_header))
										)
						send_sock.sendto(request_outer_header + request_inner_header + '1'.encode('utf-8'), (emulator_name, emulator_port))
					received_data_lock.release()
					if packet_type == 'E':
						end_time = time()
						with open(filename, "a") as copied_file:
							current_sender_data = payload_data[sender_tuple]
							for i in sorted(current_sender_data.keys()):
								copied_file.write(current_sender_data[i])
						duration = end_time - sender_start_times[sender_tuple]
						print("\n\n")
						print("="*60)
						print("Summary of Sender")
						print(f"Sender addr:                {actual_sender_ip}:{actual_sender_port}")
						print(f"Total Data Packets:         {count - 1}")
						print(f"Total Data Bytes:           {length_of_payload}")
						print(f"Average packets/second:     {math.ceil((count - 1) / float(duration)) if duration != 0 else 1}")
						print(f"Total Duration of the test: {round(duration*1000, 2)} ms")
						print("="*60)
						print("\n\n")
						number_of_trackers -= 1
						if number_of_trackers == 0:
							return
			except BlockingIOError as bie:
				pass
	except Exception as ex:
		raise ex
	finally:
		if sock is not None:
			sock.close()
		if send_sock is not None:
			send_sock.close()


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
		# receiver_thread = Thread(target=receive_data, args=[socket.gethostbyname(socket.gethostname()), waiting_port, file_to_request,
		# 								 tracker_data,
		# 								 window, emulator_host, emulator_port])
		# receiver_thread.start()
		# self_ip = socket.gethostbyname("127.0.0.1")
		# self_name = "localhost"
		self_name = socket.gethostname()
		self_ip = socket.gethostbyname(self_name)
		t2 = Thread(target=send_hello_message, args = [self_ip,waiting_port,emulator_host,emulator_port],daemon=True)
		t2.start()
		print("Thread started....")
		print(tracker_data)
		for filtered_host_info in tracker_data:
			print("In hereee")
			# print(f"Requesting file: {filtered_host_info[0]} Chunk ID: {filtered_host_info[1]} from Host {filtered_host_info[2]} {(socket.gethostbyname(filtered_host_info[2]))} @ port {filtered_host_info[3]}")
			# send_thread = Thread(target=send_ack, daemon=True, args=(socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3], emulator_host, emulator_port, 1, waiting_port))
			# send_thread.start()
			# threads.append(send_thread)
			send_request('R',socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3], file_to_request, emulator_host, emulator_port, 1, window, waiting_port)
		receive_data(socket.gethostbyname(socket.gethostname()), waiting_port, file_to_request,
										 tracker_data,
		 								 window, emulator_host, emulator_port)
		t2.join()
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

