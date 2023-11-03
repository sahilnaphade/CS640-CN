import socket
import struct
import os
import time
import datetime
import math
import argparse

def send_request_ack(packet_type,Sender_IP, sender_port, filename, window,sequence_number):
	#print("Sending request to {} on port {}".format(Sender_IP, sender_port))
	try:
		sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
		seq_no = socket.htonl(0)
		if packet_type == 'R':
			request_header = str(packet_type).encode("utf-8") + struct.pack('II', seq_no, window)
			print("Request sent \n")

		elif packet_type == 'A':
			request_header = str(packet_type).encode("utf-8") + struct.pack('II', sequence_number, 0)
			print(f"ACK sent for {sequence_number} \n")

		sock.sendto(request_header + bytes(filename, 'utf-8'), (Sender_IP,sender_port))
		
		sock.close()
	except Exception as ex:
		raise ex


def receive_data(UDP_IP, UDP_PORT, filename,Sender_IP, sender_port,window):
	try:
		sock = socket.socket(socket.AF_INET, # Internet
							socket.SOCK_DGRAM) # UDP
		# print("Requster waiting on IP {} @ port {}".format(UDP_IP, UDP_PORT))
		sock.bind(('0.0.0.0', UDP_PORT))
		start_time = None
		count = 0
		length_of_payload = 0
		received_data = {}
		while True:
			data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes

			packet_type = data[0:1].decode('utf-8')
			header = data[1:9]
			header = struct.unpack('II',header)
			sequence_number_network = header[0]
			packet_length = header[1]
			sequence_number = socket.ntohl(sequence_number_network)
			count = count + 1
			length_of_payload = length_of_payload + packet_length

			if start_time is None and packet_length > 0:
				start_time = time.time()
			payload = data[9:].decode('utf-8')
			#payload = str(data[9:])
			print(f"Packet Type:    {packet_type}")
			print(f"Recv Time:      {str(datetime.datetime.now())}")
			print(f"Sender Addr:    {addr[0]}:{addr[1]}")
			print(f"Seq No:         {sequence_number}")
			print(f"Length:         {packet_length}")
			print(f"Payload:        {data[9:(9+4)].decode('utf-8')}")

			if packet_type == 'D':
				if bool(received_data) == False:
					received_data[sequence_number] = payload
					send_request_ack('A',Sender_IP, sender_port, filename, window,sequence_number)
					with open(filename, "a") as copied_file:
						copied_file.write(payload)
					print("\n")

				elif (sequence_number in received_data):
					send_request_ack('A',Sender_IP, sender_port, filename, window,sequence_number)
				else:
					received_data[sequence_number] = payload
					send_request_ack('A',Sender_IP, sender_port, filename, window,sequence_number)
					with open(filename, "a") as copied_file:
						copied_file.write(payload)
					print("\n")

			if packet_type == 'E':
				end_time = time.time()
				if start_time is None:
					# case where the file does not exist on the sender
					start_time = end_time
				duration = end_time - start_time
				break

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


def main(waiting_port, file_to_request, window):
	tracker_data = []
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
			send_request_ack('R',socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3], file_to_request, window,1)
			receive_data(socket.gethostbyname(socket.gethostname()), waiting_port, file_to_request,socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3],1)
	else:
		raise Exception("Tracker file does not exist.")


if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Receive chunks of a file from different senders")
	parser.add_argument("-p", "--port", dest='port', type=int, required=True, help="Port number on which the requester waits for packets")
	parser.add_argument("-o", "--file-option", dest='file_option', type=str, required=True, help="File name to get the data for")
	parser.add_argument("-w", "--window_size", dest='window', type=int, required=True, help="Window size to request data")
	args = parser.parse_args()
	if args.port not in range(2050, 65536):
		raise Exception("Port number should be in the range 2050 to 65535. Passed: {}".format(args.port))
	main(args.port, args.file_option, args.window)

