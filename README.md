1. Startup server and copy password
2. Startup client with password
3. Server checks sequence number and password
4. Server writes a message to stdout if it deviates more than 3 packets
5. Server responds to client packet with the sequence number of the packet received
6. Client writes a message to stdout if it deviates more than 3 packets
