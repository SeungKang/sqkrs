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
- press i to enable verbose while plike is running, basic summary output of plike session (% packet loss, when it occurred, average time)
- logging when packet loss has been repeatedly occurring
- press v to enable verbose while plike is running
- verbose mode when it is in losing packets state
- chaos mode that purposely loses packets, misses sequence numbers, sends delayed or out of order
- breaking the code up into smaller libraries within the project

Make this into a library

```rust
#[derive(Clone)]
struct TLV {
    data_type: u16,
    len: u32,
    val: [u8],
}

// parsing a TLV from a series of bytes
// parsing several TLVs from a series of bytes

struct TLV_parser {
    cursor: io::Cursor<Vec<u8>>
}

impl TLV_parser {

}
```
