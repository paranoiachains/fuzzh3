use indicatif::{ProgressBar, ProgressStyle};

use crate::client::{self, ClientError, http};
use std::ops::RangeInclusive;
use std::{fs::File, io::BufRead, io::BufReader};

use std::io::Read;
use std::io::Write;

pub struct Fuzzer {
    wordlist: BufReader<File>,
    client: client::Client,
    matcher: Matcher,
    progress: ProgressBar,
}

impl Fuzzer {
    pub fn new(client: client::Client, wordlist_path: &str) -> std::io::Result<Self> {
        log::info!("reading wordlist at {}", wordlist_path);

        let total = count_lines(wordlist_path)?;

        let file = File::open(wordlist_path)?;
        let reader = BufReader::new(file);

        let progress = ProgressBar::new(total);
        progress.set_style(
            ProgressStyle::with_template(
                "[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} ({percent}%) ETA {eta}",
            )
            .unwrap()
            .progress_chars("##~"),
        );

        let matcher = Matcher::new(None);

        Ok(Self {
            wordlist: reader,
            client,
            matcher,
            progress,
        })
    }

    pub fn fuzz(&mut self, base_req: http::Request) -> anyhow::Result<()> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        let mut pending = Vec::new();

        for line in self.wordlist.by_ref().lines() {
            let word = line?.trim().to_string();
            pending.push(word);
        }

        while !pending.is_empty() || self.client.has_in_flight() {
            self.client.poll_io()?;

            for resp in self.client.poll_responses()? {
                if self.matcher.matches(&resp) {
                    writeln!(out, "[{}] /{}", resp.status, pending.last().unwrap())?;
                }
                self.progress.inc(1);
            }

            while let Some(word) = pending.last() {
                let req = base_req.with_path(word);

                match self.client.send_request(&req) {
                    Ok(_) => {
                        pending.pop();
                    }

                    Err(ClientError::InFlightFull | ClientError::WouldBlock) => {
                        break; // backpressure, retry later
                    }

                    Err(e) => return Err(e.into()),
                }
            }
        }

        self.progress.finish_with_message("done fuzzing");
        Ok(())
    }
}

pub struct Matcher {
    codes: Vec<std::ops::RangeInclusive<u16>>,
}

impl Matcher {
    pub fn new(codes: Option<Vec<RangeInclusive<u16>>>) -> Self {
        let codes = codes.unwrap_or_else(|| {
            vec![
                200..=299,
                301..=302,
                307..=307,
                401..=401,
                403..=403,
                405..=405,
                500..=500,
            ]
        });

        Self { codes }
    }

    pub fn matches(&self, resp: &http::Response) -> bool {
        self.codes.iter().any(|r| r.contains(&resp.status))
    }
}

fn count_lines(path: &str) -> std::io::Result<u64> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count() as u64)
}
