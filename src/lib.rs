use std::collections::HashMap;

use clap::Parser;

use client::http;

mod client;
mod config;
mod fuzz;

pub fn run() -> anyhow::Result<()> {
    // parse cli args
    let args = config::Args::parse();

    let url = url::Url::parse(args.url.as_str())?;
    let config = config::QuicConfig::new(&url, args.no_verify)?;
    let client = client::Client::new(config)?;

    let headers = parse_headers(&args.headers)?;
    let method = match args.method {
        config::Method::Get => "GET",
        config::Method::Put => "PUT",
        config::Method::Post => "POST",
        config::Method::Delete => "DELETE",
    };

    let base_req = http::Request::new(
        url.scheme(),
        url.host_str().unwrap(),
        method,
        url.path(),
        headers,
    )?;

    let mut fuzzer = fuzz::Fuzzer::new(client, &args.wordlist)?;
    fuzzer.fuzz(base_req)?;

    Ok(())
}

fn parse_headers(headers: &[String]) -> anyhow::Result<HashMap<String, String>> {
    let mut map = HashMap::new();

    for h in headers {
        let (key, value) = h
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("invalid header format: {}", h))?;

        map.insert(key.trim().to_string(), value.trim().to_string());
    }

    Ok(map)
}
