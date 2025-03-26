use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream};

use base64::{Engine, prelude::BASE64_STANDARD};
use clap::{ArgAction, Parser};
use dns_update::{DnsRecord, DnsUpdater, TsigAlgorithm};
use log::debug;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    #[arg(short, long)]
    pub server: String,
    #[arg(short, long)]
    pub origin: String,
    #[arg(short, long)]
    pub key: String,
    #[arg(short, long)]
    pub name: Option<String>,
    #[arg(short, long)]
    pub ip: Option<String>,
    #[arg(short, long, action = ArgAction::Count)]
    verbose: u8,
}

fn get_local_ip_for_remote_ip(remote_addr: &str) -> io::Result<IpAddr> {
    let remote: SocketAddr = remote_addr.parse().unwrap();
    let stream = TcpStream::connect(&remote)?;
    let local_addr = stream.local_addr()?;
    Ok(local_addr.ip())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    init_logger(args.verbose);

    let hostname = args
        .name
        .unwrap_or_else(|| hostname::get().unwrap().to_string_lossy().to_string());
    debug!("hostname: {:?}", hostname);
    let ip = match args.ip {
        Some(ip) => ip.parse().expect("IP should be parsed succeffully"),
        None => {
            let remote = format!("{}:{}", args.server, 53);
            match get_local_ip_for_remote_ip(&remote) {
                Ok(ip) => ip,
                Err(err) => {
                    panic!("failed to get IP: {err}");
                }
            }
        }
    };
    debug!("ip: {:?}", ip);
    // Create a new RFC2136 client
    let tsig = std::env::var("DNS_TSIG_KEY").expect("env variable `DNS_TSIG_KEY` should be set");
    let sig = BASE64_STANDARD.decode(tsig).unwrap();
    let client =
        DnsUpdater::new_rfc2136_tsig(args.server, args.key, sig, TsigAlgorithm::HmacSha256)
            .unwrap();

    // Delete the record
    client.delete(&hostname, &args.origin).await.unwrap();

    // Create a new A record
    let record = match ip {
        IpAddr::V4(ipv4_addr) => DnsRecord::A { content: ipv4_addr },
        IpAddr::V6(ipv6_addr) => DnsRecord::AAAA { content: ipv6_addr },
    };
    client
        .update(&hostname, record, 300, args.origin)
        .await
        .unwrap();
}

fn init_logger(level: u8) {
    let filter_level = match level {
        0 => log::LevelFilter::Info,
        1 => log::LevelFilter::Debug,
        _ => log::LevelFilter::Trace,
    };

    env_logger::builder().filter_level(filter_level).init();
}
