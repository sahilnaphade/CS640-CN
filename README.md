# CS640-CN

This is repository for the assignments perfored for CS-640, Intro to Computer Networks under Prof. Paul Barford, Fall 2023.

The problem statements of the assignments are as follows:
1. The "sender" and the "requester". 
    1. The sender will chunk a requested file and send each file chunk via UDP packets to the requester. 
    2. The requester will receive these packets, subsequently write it to a file and print receipt information. 
    3. The file transfer is distributed meaning that the requester may need to connect to different senders to get parts of the file and then assemble these parts to get the whole file. 
2. Implement a network emulator and add reliable transfer to your distributed file transfer in the previous assignment
    1. A network emulator, which delivers packets between sender(s) and requester(s) created for the first programming assignment. The senders and requesters will have additional requirements to support the network emulator.
    2. The network emulator will receive a packet, decide where it is to be forwarded, and, based on the packet priority level, queue it for sending. Upon sending, the packet will be delayed to simulate link bandwidth, and randomly drop packets to simulate a lossy link.
    3. Packets also have three different priorities and separate, fixed-size queues. If the outbound queue for a particular priority level is full, the packet will be dropped. Higher priority packets are always forwarded before lower priority packets. 
3. Modify the emulators implemented in project 2, to perform a link-state routing protocol to determine the shortest paths between a fixed, known set of nodes in the lab. The paths between the nodes will be reconfigurable and new routes must stabilize within a fixed time period.
Your emulators will also forward packets from the routetrace application that you will build to the node which is the next hop in the shortest path to a specified destination.

Me and @byoganand worked on these project together.