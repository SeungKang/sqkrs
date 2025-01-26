# udpong

`udpong` is a tool for monitoring and logging UDP flow quality.

It provides a client and server to identify and log inconsistencies in
UDP traffic, such as connection losses or out-of-order packets.

    Disclaimer: This project is in early stages, with features still in
    development and subject to change.

## Features

- HMAC Authentication: Ensures secure communication between the client
  and server.
- Password Support: The client and server share a password, set via the
  UDPONG_PW environment variable. The server generates a random password if
  UDPONG_PW is not set.

### Prerequisite

- [Rust](https://doc.rust-lang.org/cargo/getting-started/installation.html) must be installed.

## Installation

Install from a copy of the source code:

```sh
git clone https://github.com/SeungKang/udpong
cd sbtar
cargo install --path .
```

## Usage

```sh
SYNOPSIS
  udpong <COMMAND>

COMMANDS
  client [OPTIONS] <ADDRESS>
    OPTIONS
      -v, --verbose      enable verbose logging
      -b, --bind <BIND>  address of incoming request [default: 0.0.0.0:55101]
      -h, --help         Print help

  server [OPTIONS]
    OPTIONS
      -v, --verbose      enable verbose logging
      -b, --bind <BIND>  address of client [default: 0.0.0.0:55101]
      -h, --help         Print help

  version
  help     Print this message or the help of the given subcommand(s)

OPTIONS
  -h, --help     Print help
  -V, --version  Print version
```

## Examples

Using default client and server address. Running udpong in verbose mode.

```console
# on server computer
cargo run server -v
2025/01/01 01:35:25Z password is: happypossomsjumpinginthepond
2025/01/01 01:35:25Z listening on 127.0.0.1:55101 for connections...

# on client computer
export UDPONG_PW=happypossomsjumpingintheforest
cargo run -- client 127.0.0.1:55111 -v
```

Using custom client and server address.

```console
# on server computer
cargo run server --bind 127.0.0.1:55111
2025/01/01 01:35:25Z password is: happypossomsjumpinginthepond
2025/01/01 01:35:25Z listening on 127.0.0.1:55111 for connections...

# on client computer
export UDPONG_PW=happypossomsjumpingintheforest
cargo run -- client --bind 127.0.0.1:2000 127.0.0.1:55111
```
