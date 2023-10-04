import socket
import struct
import time

def receive_data(UDP_IP,UDP_PORT):
    sock = socket.socket(socket.AF_INET, # Internet
                        socket.SOCK_DGRAM) # UDP


    sock.bind((UDP_IP, UDP_PORT))

    while True:
        data, addr = sock.recvfrom(1024) # buffer size is 1024 bytes
        
        packet_type = data[0:1].decode('utf-8')
        header = data[1:9]
        header = struct.unpack('II',header)
        sequence_number_network = header[0]
        sequence_number = socket.ntohl(sequence_number_network)
        #packet_length = struct.unpack('!I', data[5:9])[0]
        packet_length = header[1]

        print("Packet type is : %s"% packet_type)
        print("Sequence number is : %d" % sequence_number)
        print("Payload is : %s "% data[9:].decode('utf-8'))
        print("\n")
    
        sock.close()
        return packet_type

def create_header(packet_type, sequence_number, payload_length):
    sequence_number_network = socket.htonl(sequence_number)
    header = str(packet_type).encode("utf-8") + struct.pack('II', sequence_number_network,payload_length)
    return header

def send_packets(packet_type,UDP_IP,UDP_PORT,sequence_number,payload_length,rate,MESSAGE):
    sock = socket.socket(socket.AF_INET, # Internet
                      socket.SOCK_DGRAM) # UDP
    sock.bind((UDP_IP, 5000))
    chunks = [MESSAGE[i:i + payload_length] for i in range(0, len(MESSAGE), payload_length)]
    for j in chunks:
            header = create_header(packet_type,sequence_number,len(j))
            sock.sendto(header + str(j).encode("utf-8"), (UDP_IP, UDP_PORT))
            current_time = time.time()
            milliseconds = int((current_time - int(current_time)) * 1000)
            
            print("DATA Packet")
            print(f"Send Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
            print(f"Send Address:  {UDP_IP}:{UDP_PORT}")
            print(f"Seq No:   {sequence_number}")
            print(f"Length :  {len(j)}")
            print(f"Payload are:  {j[:4]}")
            print("\n")

            sequence_number = sequence_number + len(j)
            time.sleep(1/rate)

    end_header = create_header('E',sequence_number,0)
    sock.sendto(end_header + str(0).encode("utf-8"),(UDP_IP,UDP_PORT))
    
    current_time = time.time()
    milliseconds = int((current_time - int(current_time)) * 1000)
    print("END Packet")
    print(f"Send Time:   {time.strftime('%Y-%m-%d %H:%M:%S')}.{milliseconds:03d}")
    print(f"Send Address:  {UDP_IP}:{UDP_PORT}")
    print(f"Seq No:   {sequence_number}")
    print(f"Length :  {0}")
    print(f"Payload are:  {0}")
    print("\n")


def main():

    UDP_IP = "127.0.0.1"
    UDP_PORT = 5005
    MESSAGE = "Hello, World!"
    sequence_number = 0
    payload_length = 13 

    print("UDP target IP: %s" % UDP_IP)
    print("UDP target port: %s" % UDP_PORT)
    print("message: %s \n\n" % MESSAGE)

    pakcet_type = receive_data(UDP_IP,2100)
    
    
    

    if pakcet_type == 'R':
        send_packets('D',UDP_IP,UDP_PORT,sequence_number,payload_length,2,MESSAGE)

if __name__ == "__main__":
    main()