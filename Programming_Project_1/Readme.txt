This is a readme file for Programming Project 1

The code for both sender and requester is done wiht required functionalities. I am also printing the required information specified in the project description after every packet.
Sender : Add to traverse through the file and store the message in an array.
For Requester: Need to add tracker file and edit code such that requester traverses through this file and reuqests file parts in the order of ID's.

Final thing is change the implementaiton such that it take arguments. I can work on this...

From Sahil
Note: 
1. Sender side file traversal done, need to test with a large sized file (and spread across nodes/different senders)
2. Tracker file, sorting the data and file traversal done (again test with different senders)
3. There is some issue with the file data writing (writing as a string in binary representation, something like this: b"b'<TEXT>'"
Need to check what is happening here. Maybe something in parsing at the receiver?
4. I took care of the arguments part as well.