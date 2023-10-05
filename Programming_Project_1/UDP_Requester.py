import socket
import struct
import time
import datetime
import math
import argparse

def send_request(Sender_IP, requester_port, filename):
	print("Sending request to {} on port {}".format(Sender_IP, requester_port))
	sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	seq_no = socket.htonl(0)
	request_header = b'R' + struct.pack('II', seq_no, 0)

	sock.sendto(request_header + bytes(filename, 'utf-8'), (Sender_IP,requester_port))
	print("Request sent \n")
	sock.close()


def receive_data(UDP_IP,UDP_PORT, filename):
	filename = filename + "new_check.txt"
	sock = socket.socket(socket.AF_INET, # Internet
						socket.SOCK_DGRAM) # UDP
	sock.bind((UDP_IP, UDP_PORT))
	start_time = None
	count = 0
	while True:
		data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes

		packet_type = data[0:1].decode('utf-8')
		header = data[1:9]
		header = struct.unpack('II',header)
		sequence_number_network = header[0]
		packet_length = header[1]
		sequence_number = socket.ntohl(sequence_number_network)
		count = count + 1

		if start_time is None and packet_length > 0:
			start_time = time.time()
		print(type(data[9:]))
		# payload = data[9:].decode('utf-8')
		payload = str(data[9:])
		print(f"Packet Type:  {packet_type}")
		print(f"Send Time:   {str(datetime.datetime.now())}")
		print(f"Send Address:  {addr}")
		print(f"Seq No:   {sequence_number}")
		print(f"Length :  {packet_length}")
		print(f"Payload is:  {payload}")
		print(type(payload))
		with open(filename, "a") as copied_file:
			copied_file.write(payload)
		print("\n")

		if packet_type == 'E':
			end_time = time.time()
			duration = end_time - start_time
			break

	print("Summary of Sender")
	print(f"Sender Address:  {addr}")
	print(f"Total Data Packets {count - 1}")
	print(f"Total Data Bytes : {sequence_number}")
	print(f"Average packets per second : {math.ceil((count - 1) / float(duration))}")
	print(f"Total Duration : {duration}")
	sock.close()


def main(waiting_port, file_to_request):
	tracker_data = []
	with open("tracker.txt", "r") as tracker_file:
		trackings = tracker_file.readlines()
		for each_line in trackings:
			filename, chunk_id, hostname, req_port = each_line.split(" ")
			# Filter the tracker file based on the filename requested
			if filename == file_to_request:
				tracker_data.append((filename, int(chunk_id), hostname, int(req_port)))
	tracker_data.sort(key=lambda x: (x[0], x[1]))
	for filtered_host_info in tracker_data:
		print(f"Filename: {filtered_host_info[0]} Chunk ID: {filtered_host_info[1]} from Host {filtered_host_info[2]} @ port {filtered_host_info[3]}")
		send_request(socket.gethostbyname(filtered_host_info[2]), filtered_host_info[3], file_to_request)
		receive_data(socket.gethostname(), waiting_port, file_to_request)

if __name__ == "__main__":
	parser = argparse.ArgumentParser(description="Receive chunks of a file from different senders")
	parser.add_argument("-p", "--port", dest='port', type=int, required=True, help="Port number on which the requester waits for packets")
	parser.add_argument("-o", "--file-option", dest='file_option', type=str, required=True, help="File name to get the data for")
	args = parser.parse_args()
	if args.port not in range(2050, 65536):
		raise Exception("Port number should be in the range 2050 to 65535. Passed: {}".format(args.port))
	main(args.port, args.file_option)

