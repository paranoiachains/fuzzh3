#![allow(dead_code)]

use clap::Parser;
use clap::arg;
use std::net::{SocketAddrV4, ToSocketAddrs};

pub const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct QuicConfig {
    pub server_name: String,
    pub remote_addr: SocketAddrV4,
    pub verify_peer: bool,
}

impl QuicConfig {
    pub fn new(url: &url::Url, verify_peer: bool) -> anyhow::Result<Self> {
        if let (Some(host), Some(port)) = (url.host_str(), url.port_or_known_default()) {
            let remote_addr = resolve_ipv4(host, port)?[0];
            Ok(QuicConfig {
                server_name: host.to_string(),
                remote_addr,
                verify_peer: !verify_peer,
            })
        } else {
            anyhow::bail!("URL missing host or port");
        }
    }
}

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
/// QUIC/HTTP3 fuzzer
pub struct Args {
    #[arg(short, long, value_name = "URL")]
    /// URL to connect to
    pub url: String,
    #[arg(short, long, default_value_t = 443)]
    /// Target port
    pub port: u16,
    #[arg(long = "no-verify", default_value_t = false)]
    /// Don't verify server's certificate
    pub no_verify: bool,
    #[arg(short, long)]
    /// Path to wordlist
    pub wordlist: String,
    #[arg(short, long, default_value = "get")]
    /// HTTP method
    pub method: Method,
    #[arg(short = 'H', value_name = "KEY:VALUE", action = clap::ArgAction::Append)]
    /// Include headers in request
    pub headers: Vec<String>,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

fn resolve_ipv4(host: &str, port: u16) -> anyhow::Result<Vec<SocketAddrV4>> {
    let addrs = (host, port).to_socket_addrs()?;

    let v4_addrs = addrs
        .filter_map(|addr| match addr {
            std::net::SocketAddr::V4(v4) => Some(v4),
            _ => None,
        })
        .collect();

    Ok(v4_addrs)
}
