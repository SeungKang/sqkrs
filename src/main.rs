use std::{time::Duration, thread::sleep, error::Error, env};
use std::net::UdpSocket;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use rand::{thread_rng, Rng};
use rand::distr::Alphanumeric;

const SEQ_NUM_SIZE: usize = 8;
const PASSWORD_SIZE: usize = 32;
const TIMESTAMP_SIZE: usize = 16;
const MESSAGE_SIZE: usize = SEQ_NUM_SIZE + PASSWORD_SIZE + TIMESTAMP_SIZE;

struct Packet {
    seq_num: u64,
    password: String,
    timestamp: u128,
}

impl Packet {
    fn new(seq_num: u64, password: String) -> Result<Self, Box<dyn Error>> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_millis();

        Ok(Self {
            seq_num: seq_num,
            password: password,
            timestamp: timestamp,
        })
    }

    fn to_u8_array(&self) -> [u8; MESSAGE_SIZE] {
        let mut message = [0u8; MESSAGE_SIZE];
        message[0..SEQ_NUM_SIZE].copy_from_slice(&self.seq_num.to_le_bytes());

        let password_bytes = self.password.as_bytes();
        message[SEQ_NUM_SIZE..SEQ_NUM_SIZE + password_bytes.len()]
            .copy_from_slice(password_bytes);

        let timestamp_index = SEQ_NUM_SIZE + PASSWORD_SIZE;
        message[timestamp_index..timestamp_index + TIMESTAMP_SIZE].copy_from_slice(&self.timestamp.to_le_bytes());

        return message;
    }
}

fn packet_from_u8_array(bytes: &[u8]) -> Result<Packet, Box<dyn Error>> {
    if bytes.len() != MESSAGE_SIZE {
        return Err("invalid byte array size")?;
    }

    let seq_num = match bytes[0..SEQ_NUM_SIZE].try_into() {
        Ok(x) => u64::from_le_bytes(x),
        Err(err) => {
            Err(format!("failed to get sequence number - {}", err))?
        }
    };

    let password_start = SEQ_NUM_SIZE;
    let password_end = password_start + PASSWORD_SIZE;
    let password_bytes = &bytes[password_start..password_end];
    let password = String::from_utf8_lossy(password_bytes)
        .trim_end_matches(char::from(0))
        .to_string();

    let timestamp_start = password_end;
    let timestamp_end = timestamp_start + TIMESTAMP_SIZE;
    let timestamp = match bytes[timestamp_start..timestamp_end].try_into() {
        Ok(x) => u128::from_le_bytes(x),
        Err(err) => {
            Err(format!("failed to parse timestamp - {}", err))?
        }
    };

    Ok(Packet {
        seq_num: seq_num,
        password: password,
        timestamp: timestamp,
    })
}


fn main() -> Result<(), Box<dyn Error>> {
    let args = Argv::parse();

    match &args.command {
        Commands::Client {password} => client(password),
        Commands::Server => server()
    }
}

#[derive(Parser)]
#[command(version, about)]
struct Argv {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Client {
        #[arg(short, long)]
        password: String,
    },
    Server,
}

// TODO: configure random data in the message = seq# + password + rand_data
fn client(password: &String) -> Result<(), Box<dyn Error>> {
    let mut seq_num: u64 = 0;
    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let target = "127.0.0.1:55101";

    if password.len() != PASSWORD_SIZE {
        Err(format!("password must be exactly {PASSWORD_SIZE} characters long."))?
    }

    loop {
        let packet = Packet::new(seq_num, password.clone())?;
        let message = packet.to_u8_array();

        socket.send_to(&message[..], target)?;
        println!("UDP sent to: {}, password: {}", target, password);

        sleep(Duration::from_millis(500));

        seq_num += 1;
    }
}

fn server() -> Result<(), Box<dyn Error>> {
    let password = match env::var("PLIKE_PASSWORD") {
        Ok(x) => {
            if x.len() != PASSWORD_SIZE {
                Err(format!("password from environment variable is the wrong size (should be {})",
                            PASSWORD_SIZE))?
            }
            x
        },
        Err(_) => {
            thread_rng()
                .sample_iter(&Alphanumeric)
                .take(PASSWORD_SIZE)
                .map(char::from)
                .collect()
        }
    };

    eprintln!("password is: {}", password);

    let mut buf = [0; 65507];

    let socket = UdpSocket::bind("0.0.0.0:55101")?;
    eprintln!("listening on {}...", socket.local_addr()?);

    let mut last_seq_num: u64 = 0;

    loop {
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf)?;

        let packet =  match packet_from_u8_array(&buf[..number_of_bytes]) {
            Ok(x) => x,
            Err(err) => {
                eprintln!("failed to parse packet from u8 array - {}", err);
                continue;
            }
        };

        if packet.password != password {
            eprintln!("packet from {}, password incorrect >:(", src_addr);
            continue;
        }

        eprintln!("packet received");

        if packet.seq_num > last_seq_num && packet.seq_num - last_seq_num > 3 {
            eprintln!("seq_num difference is greater than 3 ({}) - possible packet loss",
                      packet.seq_num - last_seq_num);
        }

        last_seq_num = packet.seq_num;
    }
}
