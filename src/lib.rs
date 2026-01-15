use std::collections::HashMap;

use clap::Parser;

use client::http;
use std::ops::RangeInclusive;

mod client;
mod config;
mod fuzz;

pub fn run() -> anyhow::Result<()> {
    let args = config::Args::parse();

    // Parse URL and create QUIC config
    let url = url::Url::parse(&args.url)?;
    let config = config::QuicConfig::new(&url, args.no_verify)?;

    // Initialize QUIC client
    let client = client::Client::new(config)?;

    // Prepare base HTTP request
    let base_req = build_base_request(&url, args.method, &args.headers)?;

    // Create and run fuzzer
    let mut fuzzer = fuzz::Fuzzer::new(client, &args.wordlist)?;
    if let Some(match_codes) = args.match_codes {
        fuzzer.matcher = fuzzer.matcher.with_codes(parse_code_ranges(&match_codes)?);
    }
    if let Some(match_size) = args.match_size {
        fuzzer.matcher = fuzzer.matcher.with_size(parse_size_range(&match_size)?);
    }

    fuzzer.fuzz(base_req)?;

    Ok(())
}

fn build_base_request(
    url: &url::Url,
    method: config::Method,
    headers: &[String],
) -> anyhow::Result<http::Request> {
    let headers_map = parse_headers(headers)?;
    let method_str = method_to_str(method)?;
    let path = url.path();

    let host = url
        .host_str()
        .ok_or_else(|| anyhow::anyhow!("URL missing host"))?;

    http::Request::new(url.scheme(), host, method_str, path, headers_map)
}

fn method_to_str(method: config::Method) -> anyhow::Result<&'static str> {
    Ok(match method {
        config::Method::Get => "GET",
        config::Method::Put => "PUT",
        config::Method::Post => "POST",
        config::Method::Delete => "DELETE",
    })
}

fn parse_headers(headers: &[String]) -> anyhow::Result<HashMap<String, String>> {
    headers
        .iter()
        .map(|h| {
            let (k, v) = h
                .split_once(':')
                .ok_or_else(|| anyhow::anyhow!("Invalid header format: {}", h))?;

            Ok((k.trim().to_string(), v.trim().to_string()))
        })
        .collect()
}

fn parse_code_ranges(values: &[String]) -> anyhow::Result<Vec<RangeInclusive<u16>>> {
    let mut ranges = Vec::new();

    for v in values {
        if let Some((start, end)) = v.split_once('-') {
            ranges.push(start.parse()?..=end.parse()?);
        } else {
            let code: u16 = v.parse()?;
            ranges.push(code..=code);
        }
    }

    Ok(ranges)
}

fn parse_size_range(value: &String) -> anyhow::Result<RangeInclusive<usize>> {
    let (start, end) = value
        .split_once('-')
        .ok_or_else(|| anyhow::anyhow!("invalid size range: {value}"))?;

    Ok(start.parse()?..=end.parse()?)
}
