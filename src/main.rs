use base64::{Engine, prelude::BASE64_STANDARD};
use clap::Parser;
use dns_update::{DnsRecord, DnsUpdater, TsigAlgorithm};

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
    pub ip: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let hostname = args
        .name
        .unwrap_or_else(|| hostname::get().unwrap().to_string_lossy().to_string());
    debug!("hostname: {:?}", hostname);
    // Create a new RFC2136 client
    let tsig = std::env::var("DNS_TSIG_KEY").expect("env variable `DNS_TSIG_KEY` should be set");
    let sig = BASE64_STANDARD.decode(tsig).unwrap();
    let client =
        DnsUpdater::new_rfc2136_tsig(args.server, args.key, sig, TsigAlgorithm::HmacSha256)
            .unwrap();

    // Delete the record
    client.delete(&hostname, &args.origin).await.unwrap();

    // Create a new A record
    client
        .update(
            &hostname,
            DnsRecord::A {
                content: args.ip.parse().expect("IP should be parsed succeffully"),
            },
            300,
            args.origin,
        )
        .await
        .unwrap();
}
