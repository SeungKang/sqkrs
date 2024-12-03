use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::{env, error::Error, io, thread, thread::sleep};

use chrono::{Utc};
use clap::{Args, Parser, Subcommand};
use rand::distr::Alphanumeric;
use rand::{thread_rng, Rng};
use sha2::Sha256;
use hmac::{Hmac, Mac};

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
}

#[derive(Args)]
struct ServerArgs {
    #[arg(short, long)]
    verbose: bool,
}

#[derive(Args)]
struct ClientArgs {
    #[arg(short, long)]
    password: String,
    #[arg(short, long)]
    verbose: bool,
    address: String,
}

type HmacSha256 = Hmac<Sha256>;

const TIMESTAMP_FORMAT: &str = "%Y/%m/%d %H:%M:%S";

fn log(message: &str) {
    let timestamp = Utc::now().format(TIMESTAMP_FORMAT);
    eprintln!("{} {}", timestamp, message);
}

fn main() -> Result<(), Box<dyn Error>> {
    if let Err(err) = main_with_error() {
        log(&format!("An error occurred: {}", err));
        return Err(err);
    }

    Ok(())
}

fn main_with_error() -> Result<(), Box<dyn Error>> {
    let args = Argv::parse();

    match &args.command {
        Commands::Client(args) => client(args),
        Commands::Server(args) => server(args),
    }?;

    Ok(())
}

// TODO: configure random data in the message = seq# + password + rand_data
fn client(args: &ClientArgs) -> Result<(), Box<dyn Error>> {
    let mut seq_num: u64 = 0;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut buf = [0; 65507];

    // TODO: Support adjustable timeout or scaling
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;

    loop {
        let packet = Packet::new(seq_num)?;
        let message = packet.to_u8_array(&args.password)
            .map_err(|err| format!("failed to turn packet to u8 array - {err}"))?;

        if seq_num == 0 {
            log("Attempting to send packet to server...");
        }

        socket.send_to(&message[..], &args.address)?;

        let sent_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        if args.verbose {
            log(&format!(
                "UDP packet sent to: {}, seq_num: {}",
                &args.address, seq_num
            ));
        }

        let current_seq_num = seq_num;
        seq_num += 1;

        let number_of_bytes = match socket.recv(&mut buf) {
            Ok(x) => x,
            Err(err) => {
                if err.kind() == io::ErrorKind::TimedOut {
                    log(&format!(
                        "timed-out 🥺 waiting for response to: {}",
                        current_seq_num
                    ));
                    continue;
                }
                return Err(err)?;
            }
        };

        let recv_time = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        if seq_num == 1 {
            log("Server response received");
        }

        let diff = recv_time as i128 - sent_time as i128;

        if args.verbose {
            log(&format!(
                "Received packet seq_num: {}, time: {}",
                packet.seq_num, diff
            ));
        }

        if diff > 500 {
            sleep(Duration::from_millis(500));
        } else {
            sleep(Duration::from_millis((500 - diff) as u64));
        }

        let packet = match packet_from_u8_array(&buf[..number_of_bytes], &args.password) {
            Ok(x) => x,
            Err(err) => {
                log(&format!("failed to parse packet from u8 array - {}", err));
                continue;
            }
        };

        if packet.seq_num > current_seq_num && packet.seq_num - current_seq_num > 3 {
            log(&format!(
                "seq_num difference is greater than 3 ({}) - possible packet loss",
                packet.seq_num - current_seq_num
            ));
        }
    }
}

fn server(args: &ServerArgs) -> Result<(), Box<dyn Error>> {
    let password = match env::var("PLIKE_PASSWORD") {
        Ok(x) => {
            if x.len() == 0 {
                Err("password from environment variable is empty")?
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

    let mut buf = [0; 65507];

    let socket = UdpSocket::bind("0.0.0.0:55101")?;
    log(&format!(
        "Listening on {} for connections...",
        socket.local_addr()?
    ));

    let clients: Arc<Mutex<HashMap<SocketAddr, ClientState>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let clients_clone = clients.clone();
    thread::spawn(move || remove_idle_clients(clients_clone));

    loop {
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf)?;

        let packet = match packet_from_u8_array(&buf[..number_of_bytes], &password) {
            Ok(x) => x,
            Err(err) => {
                log(&format!("failed to parse packet from u8 array - {}", err));
                continue;
            }
        };

        if args.verbose {
            log(&format!(
                "Received packet from: {}, seq_num: {}",
                src_addr, packet.seq_num
            ));
        }

        let packet_time = Instant::now();

        let message = packet.to_u8_array(&password)
            .map_err(|err| format!("failed to turn packet to u8 array - {err}"))?;

        socket.send_to(&message[..], src_addr)?;

        if args.verbose {
            log(&format!(
                "UDP packet sent to: {}, seq_num: {}",
                src_addr, packet.seq_num
            ));
        }

        // scopes the clients lock within the curly braces
        {
            let mut clients = clients.lock().unwrap();

            if let Some(state) = clients.get_mut(&src_addr) {
                state.last_packet = packet.clone();
                state.last_packet_time = packet_time;

                if packet.seq_num > state.last_packet.seq_num
                    && packet.seq_num - state.last_packet.seq_num > 3
                {
                    log(&format!(
                        "seq_num difference is greater than 3 ({}) - possible packet loss",
                        packet.seq_num - state.last_packet.seq_num
                    ));
                }
            } else {
                clients.insert(
                    src_addr,
                    ClientState {
                        addr: src_addr,
                        last_packet: packet.clone(),
                        last_packet_time: packet_time,
                    },
                );

                log(&format!("Client connected: {}", src_addr));
            }
        }
    }
}

fn remove_idle_clients(clients: Arc<Mutex<HashMap<SocketAddr, ClientState>>>) {
    loop {
        sleep(Duration::from_secs(5));

        // clients gets unlocked at the end of this statement
        clients.lock().unwrap().retain(|addr, state| {
            if Instant::now().duration_since(state.last_packet_time) > Duration::new(60, 0) {
                log(&format!("Removing idle client: {}", addr));
                false
            } else {
                true
            }
        });
    }
}

struct ClientState {
    addr: SocketAddr,
    last_packet: Packet,
    last_packet_time: Instant,
}

#[derive(Clone)]
struct Packet {
    seq_num: u64,
    timestamp: u128,
}

impl Packet {
    fn new(seq_num: u64) -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis();

        Ok(Self {
            seq_num: seq_num,
            timestamp: timestamp,
        })
    }

    fn to_u8_array(&self, password: &str) -> Result<[u8; MESSAGE_SIZE], Box<dyn Error>> {
        let mut message = [0u8; MESSAGE_SIZE];

        message[0..SEQ_NUM_SIZE].copy_from_slice(&self.seq_num.to_le_bytes());

        message[TIMESTAMP_START..TIMESTAMP_END]
            .copy_from_slice(&self.timestamp.to_le_bytes());

        let mut mac = HmacSha256::new_from_slice(password.as_bytes())
            .map_err(|err| format!("failed to create mac - {err}"))?;

        mac.update(&message[..MAC_START]);
        message[MAC_START..MAC_END].copy_from_slice(&mac.finalize().into_bytes()[..]);

        Ok(message)
    }
}

fn packet_from_u8_array(bytes: &[u8], password: &str) -> Result<Packet, Box<dyn Error>> {
    if bytes.len() != MESSAGE_SIZE {
        return Err("invalid byte array size")?;
    }

    let received_mac = &bytes[MAC_START..MAC_END];
    let mut mac = HmacSha256::new_from_slice(password.as_bytes())
        .map_err(|err| format!("failed to create mac - {err}"))?;

    mac.update(&bytes[..MAC_START]);

    mac.verify_slice(&received_mac)
        .map_err(|err| format!("failed to verify mac slice - {err}"))?;

    let seq_num = match bytes[0..SEQ_NUM_SIZE].try_into() {
        Ok(x) => u64::from_le_bytes(x),
        Err(err) => Err(format!("failed to get sequence number - {}", err))?,
    };

    let timestamp = match bytes[TIMESTAMP_START..TIMESTAMP_END].try_into() {
        Ok(x) => u128::from_le_bytes(x),
        Err(err) => Err(format!("failed to parse timestamp - {}", err))?,
    };

    Ok(Packet {
        seq_num: seq_num,
        timestamp: timestamp,
    })
}
