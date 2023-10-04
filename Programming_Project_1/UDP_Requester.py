import socket
import struct
import time
import datetime
import math

def send_request(Sender_IP,requester_port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    seq_no = socket.htonl(0)
    request_header = b'R' + struct.pack('II',seq_no,0)

    sock.sendto(request_header + b"This is Request", (Sender_IP,requester_port))
    print("Request sent \n")
    sock.close()


def receive_data(UDP_IP,UDP_PORT):
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
        sequence_number = socket.ntohl(sequence_number_network)
        #packet_length = struct.unpack('!I', data[5:9])[0]
        packet_length = header[1]
        count = count + 1

        if start_time is None and packet_length > 0:
                start_time = time.time()
        
        print(f"Packet Type:  {packet_type}")
        print(f"Send Time:   {str(datetime.datetime.now())}")
        print(f"Send Address:  {addr}")
        print(f"Seq No:   {sequence_number}")
        print(f"Length :  {packet_length}")
        print(f"Payload are:  {data[9:(9+4)].decode('utf-8')}")
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

             

def main():
    UDP_IP = "127.0.0.1"
    UDP_PORT = 5005
    REQ_PORT = 2100
    send_request(UDP_IP,REQ_PORT)

    receive_data(UDP_IP,UDP_PORT)

if __name__ == "__main__":
    main()