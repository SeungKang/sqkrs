use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, error::Error, io, thread, thread::sleep};

use chrono::Utc;
use clap::{Args, Parser, Subcommand};
use hmac::{Hmac, Mac};
use rand::distr::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::Sha256;

const VERSION: &str = "v0.0.1";

const PASSWORD_ENV_NAME: &str = "PLIKE_PASSWORD";

const SEQ_NUM_SIZE: usize = 8;
const SEQ_NUM_START: usize = 0;
const SEQ_NUM_END: usize = SEQ_NUM_START + SEQ_NUM_SIZE;

const TIMESTAMP_SIZE: usize = 16;
const TIMESTAMP_START: usize = SEQ_NUM_SIZE;
const TIMESTAMP_END: usize = TIMESTAMP_START + TIMESTAMP_SIZE;

const MAC_SIZE: usize = 32;
const MAC_START: usize = MESSAGE_SIZE - MAC_SIZE;
const MAC_END: usize = MAC_START + MAC_SIZE;

const MESSAGE_SIZE: usize = SEQ_NUM_SIZE + TIMESTAMP_SIZE + MAC_SIZE;

#[derive(Parser)]
#[command(version, about)]
struct Argv {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Client(ClientArgs),
    Server(ServerArgs),
    Version,
}

#[derive(Args)]
struct ServerArgs {
    #[arg(short, long)]
    verbose: bool,
    #[arg(short, long, default_value = "0.0.0.0:55101")]
    bind: String,
}

#[derive(Args)]
struct ClientArgs {
    #[arg(short, long)]
    verbose: bool,
    address: String,
}

type HmacSha256 = Hmac<Sha256>;

const TIMESTAMP_FORMAT: &str = "%Y/%m/%d %H:%M:%SZ";

fn log(message: &str) {
    let timestamp = Utc::now().format(TIMESTAMP_FORMAT);
    eprintln!("{} {}", timestamp, message);
}

fn main() -> Result<(), Box<dyn Error>> {
    if let Err(err) = main_with_error() {
        log(&format!("fatal: {}", err));
        return Err(err);
    }

    Ok(())
}

fn main_with_error() -> Result<(), Box<dyn Error>> {
    let args = Argv::parse();

    match &args.command {
        Commands::Client(args) => client(args),
        Commands::Server(args) => server(args),
        Commands::Version => version(),
    }?;

    Ok(())
}

fn version() -> Result<(), Box<dyn Error>> {
    println!("{VERSION}");

    Ok(())
}

// TODO: configure random data in the message = seq# + password + rand_data
fn client(args: &ClientArgs) -> Result<(), Box<dyn Error>> {
    let password = match env::var(PASSWORD_ENV_NAME) {
        Ok(x) => {
            if x.is_empty() {
                Err(format!(
                    "password from {PASSWORD_ENV_NAME} environment variable is empty"
                ))?
            }
            x
        }
        Err(_) => {
            Err(format!(
                "please provide a password by setting the {PASSWORD_ENV_NAME} environment variable"
            ))
        }?,
    };

    let addr: SocketAddr = args
        .address
        .parse()
        .map_err(|err| format!("failed to parse listen address - {err}"))?;

    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|err| format!("failed to create udp socket - {err}"))?;

    // TODO: Support adjustable timeout or scaling
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|err| format!("failed to set the read timeout of socket - {err}"))?;

    log("attempting to send initial message to server...");

    let mut state = ClientState::new(addr, ClientThresholds::new());
    let mut buf = [0; 65507];

    loop {
        let msg = Message::new(state.seq_num)
            .map_err(|err| format!("failed to create new message - {err}"))?;

        let message = msg
            .to_u8_array(&password)
            .map_err(|err| format!("failed to turn message into u8 array - {err}"))?;

        socket
            .send_to(&message[..], &args.address)
            .map_err(|err| format!("failed to send message to server - {err}"))?;

        let sent_at = Instant::now();

        state.sent_message();

        if args.verbose {
            log(&format!(
                "message sent to: {}, seq_num: {}",
                &args.address, state.need_seq_num
            ));
        }

        let (n_bytes, from_addr) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(err) => {
                if err.kind() == io::ErrorKind::TimedOut {
                    state.timed_out_packet_loss();

                    if args.verbose {
                        log(&format!(
                            "timed-out 🥺 waiting for response to: {}",
                            state.need_seq_num
                        ));
                    }

                    continue;
                } else if let Some(libc::EAGAIN) = err.raw_os_error() {
                    state.timed_out_packet_loss();

                    if args.verbose {
                        log(&format!(
                            "got EAGAIN when waiting for response message ({}): {}",
                            err, state.need_seq_num
                        ));
                    }

                    continue;
                }

                return Err(format!(
                    "socket receive failed while waiting for response message - {err}"
                ))?;
            }
        };

        let recv_at = Instant::now();
        let elapsed_ms = sent_at.elapsed().as_millis();

        if args.verbose {
            log(&format!(
                "received message seq_num: {}, elapsed: {} ms",
                msg.seq_num, elapsed_ms
            ));
        }

        if elapsed_ms > 500 {
            sleep(Duration::from_millis(500));
        } else {
            sleep(Duration::from_millis((500 - elapsed_ms) as u64));
        }

        let response = match message_from_u8_array(&buf[..n_bytes], &password) {
            Ok(x) => x,
            Err(err) => {
                log(&format!("failed to parse message from {from_addr} - {err}"));
                continue;
            }
        };

        if response.seq_num == 0 {
            log("received initial server response");
        }

        state.received_message(response, recv_at);
    }
}

fn server(args: &ServerArgs) -> Result<(), Box<dyn Error>> {
    let password = match env::var(PASSWORD_ENV_NAME) {
        Ok(x) => {
            if x.is_empty() {
                Err(format!(
                    "password from {PASSWORD_ENV_NAME} environment variable is empty"
                ))?
            }
            x
        }
        Err(_) => thread_rng()
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect(),
    };

    log(&format!("password is: {}", password));

    let socket = UdpSocket::bind(args.bind.clone())
        .map_err(|err| format!("failed to create udp socket - {err}"))?;

    let local_addr = socket
        .local_addr()
        .map_err(|err| format!("failed to get local address - {err}"))?;

    log(&format!("listening on {} for connections...", local_addr));

    let clients: Arc<Mutex<HashMap<SocketAddr, ClientState>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let clients_clone = clients.clone();
    thread::spawn(move || remove_idle_clients(clients_clone));

    let client_thresholds = ClientThresholds::new();

    let mut buf = [0; 65507];

    loop {
        let (n_bytes, src_addr) = socket
            .recv_from(&mut buf)
            .map_err(|err| format!("failed to receive from socket - {err}"))?;

        let msg = match message_from_u8_array(&buf[..n_bytes], &password) {
            Ok(x) => x,
            Err(err) => {
                log(&format!("failed to parse message from {src_addr} - {err}"));
                continue;
            }
        };

        if args.verbose {
            log(&format!(
                "received message from: {}, seq_num: {}",
                src_addr, msg.seq_num
            ));
        }

        let recv_at = Instant::now();

        // scopes the clients lock within the curly braces
        {
            let mut clients = clients.lock().unwrap();

            if let Some(state) = clients.get_mut(&src_addr) {
                state.received_message(msg.clone(), recv_at);
            } else {
                clients.insert(
                    src_addr,
                    ClientState::new_with_message(
                        src_addr,
                        client_thresholds.clone(),
                        msg.clone(),
                        recv_at,
                    ),
                );

                log(&format!("client connected: {}", src_addr));
            }
        }

        let reply = msg
            .to_u8_array(&password)
            .map_err(|err| format!("failed to turn reply into u8 array - {err}"))?;

        socket
            .send_to(&reply[..], src_addr)
            .map_err(|err| format!("failed to send reply to client - {err}"))?;

        // scopes the clients lock within the curly braces
        {
            // TODO: Is there a better way to do this that does
            // not require locking the mutex a second time?
            let mut clients = clients.lock().unwrap();

            if let Some(state) = clients.get_mut(&src_addr) {
                state.sent_reply(msg.seq_num);
            }
        }

        if args.verbose {
            log(&format!(
                "reply sent to: {}, seq_num: {}",
                src_addr, msg.seq_num
            ));
        }
    }
}

// TODO: make this customizable
fn remove_idle_clients(clients: Arc<Mutex<HashMap<SocketAddr, ClientState>>>) {
    loop {
        sleep(Duration::from_secs(5));

        // clients gets unlocked at the end of this statement
        clients.lock().unwrap().retain(|addr, state| {
            if Instant::now().duration_since(state.last_recv_time) > Duration::new(5, 0) {
                log(&format!("removing idle client: {}", addr));
                false
            } else {
                true
            }
        });
    }
}

struct ClientState {
    addr: SocketAddr,
    thresholds: ClientThresholds,
    seq_num: u64,
    need_seq_num: u64,
    last_msg: Message,
    last_recv_time: Instant,
    losing_packets: bool,
    num_lost_packets: u64,
}

impl ClientState {
    fn new_with_message(
        addr: SocketAddr,
        thresholds: ClientThresholds,
        msg: Message,
        recv_at: Instant,
    ) -> ClientState {
        let mut state = ClientState::new(addr, thresholds);

        state.seq_num = msg.seq_num;
        state.need_seq_num = msg.seq_num + 1;
        state.last_msg = msg;
        state.last_recv_time = recv_at;

        state
    }

    fn new(addr: SocketAddr, thresholds: ClientThresholds) -> ClientState {
        Self {
            thresholds: thresholds,
            addr: addr,
            seq_num: 0,
            need_seq_num: 0,
            last_msg: Message::empty(),
            last_recv_time: Instant::now(),
            losing_packets: false,
            num_lost_packets: 0,
        }
    }

    fn sent_message(&mut self) {
        self.need_seq_num = self.seq_num;
        self.seq_num += 1;
    }

    fn sent_reply(&mut self, current_seq_num: u64) {
        self.need_seq_num = current_seq_num + 1;
        self.seq_num = current_seq_num;
    }

    fn received_message(&mut self, msg: Message, when: Instant) {
        if msg.seq_num != self.need_seq_num {
            self.out_of_order_packet_loss(msg.clone());

            self.last_msg = msg;
            self.last_recv_time = when;

            return;
        }

        // TODO: Maybe we should decrement by one and check if still losing packets?
        if self.losing_packets {
            log(&format!(
                "no longer losing packets :) - lost {} packets, current sequence num is {}",
                self.num_lost_packets, msg.seq_num
            ));
        }

        self.losing_packets = false;
        self.num_lost_packets = 0;

        self.last_msg = msg;
        self.last_recv_time = when;
    }

    fn out_of_order_packet_loss(&mut self, msg: Message) {
        if self.losing_packets {
            return;
        }

        if msg.seq_num > self.need_seq_num {
            let diff = msg.seq_num - self.need_seq_num;

            if diff > self.thresholds.max_seq_num_diff {
                log(&format!(
                    "possible packet loss: received packet with sequence number {}, which is {} greater than expected ({})",
                    msg.seq_num, diff, self.need_seq_num
                ))
            }
        } else {
            let diff = self.need_seq_num - msg.seq_num;

            if diff > self.thresholds.max_seq_num_diff {
                log(&format!(
                    "possible packet loss: received packet with sequence number {}, which is {} lower than expected ({})",
                    msg.seq_num, diff, self.need_seq_num
                ))
            }
        }
    }

    fn timed_out_packet_loss(&mut self) {
        let new_loss_total = self.num_lost_packets + 1;

        if !self.losing_packets && new_loss_total > self.thresholds.max_lost_packets {
            self.losing_packets = true;

            log(&format!(
                "losing packets >:( - timed-out waiting for sequence number {}, \
                 max allowed missing packets is {}",
                self.need_seq_num, self.thresholds.max_lost_packets,
            ));
        }

        self.num_lost_packets = new_loss_total;
    }
}

#[derive(Clone)]
struct ClientThresholds {
    max_seq_num_diff: u64,
    max_lost_packets: u64,
}

impl ClientThresholds {
    fn new() -> ClientThresholds {
        Self {
            max_seq_num_diff: 10,
            max_lost_packets: 10,
        }
    }
}

#[derive(Clone)]
struct Message {
    seq_num: u64,
    timestamp: u128,
}

impl Message {
    fn new(seq_num: u64) -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|err| format!("failed to get duration since UTC - {err}"))?
            .as_millis();

        Ok(Self {
            seq_num: seq_num,
            timestamp: timestamp,
        })
    }

    fn empty() -> Message {
        Message {
            seq_num: 0,
            timestamp: 0,
        }
    }

    fn to_u8_array(&self, password: &str) -> Result<[u8; MESSAGE_SIZE], Box<dyn Error>> {
        let mut message = [0u8; MESSAGE_SIZE];

        message[SEQ_NUM_START..SEQ_NUM_END].copy_from_slice(&self.seq_num.to_le_bytes());

        message[TIMESTAMP_START..TIMESTAMP_END].copy_from_slice(&self.timestamp.to_le_bytes());

        let mut mac = HmacSha256::new_from_slice(password.as_bytes())
            .map_err(|err| format!("failed to create mac - {err}"))?;

        mac.update(&message[..MAC_START]);
        message[MAC_START..MAC_END].copy_from_slice(&mac.finalize().into_bytes()[..]);

        Ok(message)
    }
}

fn message_from_u8_array(bytes: &[u8], password: &str) -> Result<Message, Box<dyn Error>> {
    if bytes.len() != MESSAGE_SIZE {
        Err("invalid byte array size")?;
    }

    let received_mac = &bytes[MAC_START..MAC_END];
    let mut mac = HmacSha256::new_from_slice(password.as_bytes())
        .map_err(|err| format!("failed to create mac - {err}"))?;

    mac.update(&bytes[..MAC_START]);

    mac.verify_slice(&received_mac)
        .map_err(|err| format!("failed to verify mac slice - {err}"))?;

    let seq_num = match bytes[SEQ_NUM_START..SEQ_NUM_END].try_into() {
        Ok(x) => u64::from_le_bytes(x),
        Err(err) => Err(format!("failed to get sequence number - {}", err))?,
    };

    let timestamp = match bytes[TIMESTAMP_START..TIMESTAMP_END].try_into() {
        Ok(x) => u128::from_le_bytes(x),
        Err(err) => Err(format!("failed to parse timestamp - {}", err))?,
    };

    Ok(Message {
        seq_num: seq_num,
        timestamp: timestamp,
    })
}
