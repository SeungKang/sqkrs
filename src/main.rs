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
            if x.len() == 0 {
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

    let socket = UdpSocket::bind("0.0.0.0:0")
        .map_err(|err| format!("failed to create udp socket - {err}"))?;

    // TODO: Support adjustable timeout or scaling
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .map_err(|err| format!("failed to set the read timeout of socket - {err}"))?;

    log("attempting to send initial message to server...");

    let mut seq_num: u64 = 0;
    let mut current_packet_loss_state = false;
    let mut last_packet_loss_state = false;
    let mut last_recv_seq_num = seq_num;
    let mut buf = [0; 65507];

    loop {
        if current_packet_loss_state != last_packet_loss_state {
            last_packet_loss_state = current_packet_loss_state;
            if current_packet_loss_state {
                log("losing packets >:(");
            } else {
                log("no longer losing packets :)");
            }
        }

        let msg =
            Message::new(seq_num).map_err(|err| format!("failed to create new message - {err}"))?;

        let message = msg
            .to_u8_array(&password)
            .map_err(|err| format!("failed to turn message into u8 array - {err}"))?;

        socket
            .send_to(&message[..], &args.address)
            .map_err(|err| format!("failed to send message to server - {err}"))?;

        let sent_at = Instant::now();

        if args.verbose {
            log(&format!(
                "message sent to: {}, seq_num: {}",
                &args.address, seq_num
            ));
        }

        seq_num += 1;

        let (n_bytes, from_addr) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(err) => {
                current_packet_loss_state = true;

                if err.kind() == io::ErrorKind::TimedOut {
                    if args.verbose {
                        log(&format!("timed-out 🥺 waiting for response to: {seq_num}"));
                    }

                    continue;
                } else if let Some(libc::EAGAIN) = err.raw_os_error() {
                    if args.verbose {
                        log(&format!(
                            "got EAGAIN when waiting for response message ({err}): {seq_num}"
                        ));
                    }

                    continue;
                }

                return Err(format!(
                    "socket receive failed while waiting for response message - {err}"
                ))?;
            }
        };

        current_packet_loss_state = false;

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

        if response.seq_num > last_recv_seq_num && response.seq_num - last_recv_seq_num > 3 {
            log(&format!(
                "seq_num difference is greater than 3 ({}) - possible packet loss",
                response.seq_num - last_recv_seq_num
            ));
        }

        last_recv_seq_num = response.seq_num;
    }
}

fn server(args: &ServerArgs) -> Result<(), Box<dyn Error>> {
    let password = match env::var(PASSWORD_ENV_NAME) {
        Ok(x) => {
            if x.len() == 0 {
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

        let reply = msg
            .to_u8_array(&password)
            .map_err(|err| format!("failed to turn reply into u8 array - {err}"))?;

        socket
            .send_to(&reply[..], src_addr)
            .map_err(|err| format!("failed to send reply to client - {err}"))?;

        if args.verbose {
            log(&format!(
                "reply sent to: {}, seq_num: {}",
                src_addr, msg.seq_num
            ));
        }

        // scopes the clients lock within the curly braces
        {
            let mut clients = clients.lock().unwrap();

            if let Some(state) = clients.get_mut(&src_addr) {
                if msg.seq_num > state.last_msg.seq_num && msg.seq_num - state.last_msg.seq_num > 3
                {
                    log(&format!(
                        "seq_num difference is greater than 3 ({}) - possible packet loss",
                        msg.seq_num - state.last_msg.seq_num
                    ));
                }

                state.last_msg = msg.clone();
                state.last_recv_time = recv_at;
            } else {
                clients.insert(
                    src_addr,
                    ClientState {
                        addr: src_addr,
                        last_msg: msg.clone(),
                        last_recv_time: recv_at,
                    },
                );

                log(&format!("client connected: {}", src_addr));
            }
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
    last_msg: Message,
    last_recv_time: Instant,
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
        return Err("invalid byte array size")?;
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
