1. Startup server and copy password
2. Startup client with password
3. Server checks sequence number and password
4. Server writes a message to stdout if it deviates more than 3 packets
5. Server responds to client packet with the sequence number of the packet received
6. Client writes a message to stdout if it deviates more than 3 packets

Client alerts when response is not receive within time limit.

## TODO
- short fixed timed udp speed test
- implement type length value for messages
- basic summary output of plike session (% packet loss, when it occurred, average time)
- logging when packet loss has been repeatedly occurring
