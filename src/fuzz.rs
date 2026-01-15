use indicatif::{ProgressBar, ProgressStyle};

use crate::client::{self, ClientError, http};
use std::collections::VecDeque;
use std::ops::RangeInclusive;
use std::{fs::File, io::BufRead, io::BufReader};

use std::io::Read;
use std::io::Write;

pub struct Fuzzer {
    pub matcher: Matcher,
    reader: BufReader<File>,
    client: client::Client,
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

        let matcher = Matcher::default();

        Ok(Self {
            reader,
            client,
            matcher,
            progress,
        })
    }

    pub fn fuzz(&mut self, base_req: http::Request) -> anyhow::Result<()> {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();

        let mut pending = VecDeque::new();

        for line in self.reader.by_ref().lines() {
            let word = line?.trim().to_string();
            pending.push_back(word);
        }

        while !pending.is_empty() || self.client.has_in_flight() {
            self.client.poll_io()?;

            for resp in self.client.poll_responses()? {
                if self.matcher.matches(&resp) {
                    writeln!(out, "[{}] {}", resp.status, resp.path)?;
                }
                self.progress.inc(1);
            }

            while let Some(word) = pending.front() {
                let req = base_req.with_path(&word);

                match self.client.send_request(&req) {
                    Ok(_) => {
                        pending.pop_front();
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
    size: Option<RangeInclusive<usize>>,
}

impl Matcher {
    pub fn with_codes(mut self, codes: Vec<RangeInclusive<u16>>) -> Self {
        self.codes = codes;
        self
    }

    pub fn with_size(mut self, size: RangeInclusive<usize>) -> Self {
        self.size = Some(size);
        self
    }

    pub fn matches(&self, resp: &http::Response) -> bool {
        if !self.codes.iter().any(|r| r.contains(&resp.status)) {
            return false;
        }

        if let Some(ref size) = self.size {
            size.contains(&resp.body.len())
        } else {
            true
        }
    }
}

impl Default for Matcher {
    fn default() -> Self {
        let codes = vec![
            200..=299,
            301..=302,
            307..=307,
            401..=401,
            403..=403,
            405..=405,
            500..=500,
        ];

        Self { codes, size: None }
    }
}

fn count_lines(path: &str) -> std::io::Result<u64> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count() as u64)
}
