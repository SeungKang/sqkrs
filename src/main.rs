use std::{time::Duration, thread::sleep, error::Error};
use std::fmt::format;
use std::net::UdpSocket;
use clap::{Parser, Subcommand};
use rand::{thread_rng, Rng};
use rand::distr::Alphanumeric;

const PASSWORD_LENGTH: usize = 24;

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

    if password.len() != PASSWORD_LENGTH {
        return Err(format!("password must be exactly {} characters long.", PASSWORD_LENGTH).into());
    }

    loop {
        let bytes = seq_num.to_le_bytes();
        let password_bytes = password.as_bytes();

        let mut message = [0u8;32];

        message[0..8].clone_from_slice(&bytes);
        message[8..(8 + PASSWORD_LENGTH)].clone_from_slice(password_bytes);

        socket.send_to(&message, target)?;
        println!("UDP sent to: {}, password: {}", target, password);

        sleep(Duration::from_millis(500));

        seq_num += 1;
    }
}

fn server() -> Result<(), Box<dyn Error>> {
    let password: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(PASSWORD_LENGTH)
        .map(char::from)
        .collect();

    eprintln!("generated password is: {}", password);

    let mut buf = [0; 65507];

    let socket = UdpSocket::bind("0.0.0.0:55101")?;
    eprintln!("listening on {}...", socket.local_addr()?);

    let mut last_seq_num: u64 = 0;

    loop {
        let (number_of_bytes, src_addr) = socket.recv_from(&mut buf)?;
        let filled_buf = &buf[..number_of_bytes];

        if filled_buf.len() < 8 + PASSWORD_LENGTH {
            eprintln!("received data is too short");
            continue;
        }

        let received_password = String::from_utf8_lossy(&filled_buf[8..(8 + PASSWORD_LENGTH)]);

        if received_password != password {
            eprintln!("password does not match: {}", received_password);
            continue;
        }

        // let seq_num = filled_buf[0..8].try_into().unwrap_or_else(|err| {
        //     eprintln!(format!("failed to get sequence number - {}", err));
        // });

        let seq_num :[u8;8] = match filled_buf[0..8].try_into() {
            Ok(x) => x,
            Err(err) => {
                eprintln!("failed to get sequence number - {}", err);
                continue;
            }
        };

        let seq_num = u64::from_le_bytes(seq_num);

        if seq_num > last_seq_num && seq_num - last_seq_num > 3 {
            eprintln!("seq_num difference is greater than 3 ({}) - possible packet loss",
                     seq_num - last_seq_num);
        }

        last_seq_num = seq_num;
    }
}

