## TODO

- short fixed timed udp speed test
- implement type length value for messages
- press i to enable verbose while sqkrs is running, basic summary output of sqkrs session (% packet loss, when it occurred, average time)
- logging when packet loss has been repeatedly occurring
- press v to enable verbose while sqkrs is running
- verbose mode when it is in losing packets state
- chaos mode that purposely loses packets, misses sequence numbers, sends delayed or out of order
- breaking the code up into smaller libraries within the project
- add capsicum and pledge support someday, and macOS sandbox framework
- user provided arguments for thresholds for logging
- don't log losing packets if initial server connection reply was never received
- changing when the round trip message time changes significantly
- extract only what we need from ClientArgs to get rid of clone

Make below into a library:

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
