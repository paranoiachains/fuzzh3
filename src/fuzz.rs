use indicatif::{ProgressBar, ProgressStyle};

use crate::client;
use std::ops::RangeInclusive;
use std::{fs::File, io::BufRead, io::BufReader};

use std::io::{self, Write};

pub struct Fuzzer {
    wordlist: BufReader<File>,
    req: client::Request,
    client: client::Client,
    matcher: Matcher,
    progress: ProgressBar,
}

impl Fuzzer {
    pub fn new(
        req: client::Request,
        client: client::Client,
        wordlist_path: &str,
    ) -> std::io::Result<Self> {
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
            req,
            client,
            matcher,
            progress,
        })
    }

    fn next_word(&mut self) -> Option<String> {
        let mut line = String::new();

        match self.wordlist.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => Some(line.trim_end().to_string()),
            Err(_) => None,
        }
    }

    pub fn start(&mut self) -> anyhow::Result<()> {
        let stdout = io::stdout();
        let mut out = stdout.lock();
        while let Some(word) = self.next_word() {
            self.progress.inc(1);

            log::debug!("current word is: {}", word);

            self.req = self.req.with_path(&word);
            let resp = match self.client.send_request(&self.req) {
                Ok(r) => r,
                Err(e) => {
                    log::warn!("request failed for {}: {}", self.req.path, e);
                    continue;
                }
            };

            let body = resp.body_to_string()?;
            let headers = resp.headers;
            let status = resp.status;
            if self.matcher.matches(status) {
                log::debug!("found match! {status}");
                writeln!(out, "[{}] {}", status, self.req.path)?;
            } else {
                log::debug!("no status match, continuing...");
            };

            log::debug!(
                "decoded response:\nStatus: {}\nHeaders: {:?}\nBody: {}",
                status,
                headers,
                body.trim_end()
            );
        }
        self.progress.finish_with_message("Done.");
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

    pub fn matches(&self, status: u16) -> bool {
        self.codes.iter().any(|r| r.contains(&status))
    }
}

fn count_lines(path: &str) -> std::io::Result<u64> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    Ok(reader.lines().count() as u64)
}
