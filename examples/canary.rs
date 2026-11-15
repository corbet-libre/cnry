//! Draw the canary in the terminal.
//!
//! `cargo run --example canary -- --key ed25519pub:... [canary.json]`
//!
//! Verifies the statement (a missing file counts as absent), then animates
//! the scene until interrupted. Without `--key` it previews the present state.

use cnry::{PublicKey, Verdict, term, verify};
use std::time::{Duration, Instant};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let key = args
        .iter()
        .position(|a| a == "--key")
        .and_then(|i| args.get(i + 1));
    let file = args
        .iter()
        .rev()
        .find(|a| !a.starts_with("--") && !a.starts_with("ed25519pub:"));
    let (present, line) = match (key, file) {
        (Some(k), file) => {
            let key = PublicKey::parse(k).expect("a valid ed25519pub: key");
            let json = file
                .and_then(|f| std::fs::read_to_string(f).ok())
                .unwrap_or_default();
            match verify(&json, &key, time::OffsetDateTime::now_utc()) {
                Verdict::Present(st) => (
                    true,
                    format!("{} (valid until {})", st.statement, st.expires),
                ),
                Verdict::Absent => (false, "No current statement.".to_string()),
            }
        }
        _ => (true, "Preview (no --key given).".to_string()),
    };
    let mode = term::ColorMode::detect();
    let start = Instant::now();
    print!("\x1b[2J\x1b[?25l");
    for _ in 0..2400 {
        let t = start.elapsed().as_secs_f64();
        print!("\x1b[H{}\n\n{line}\x1b[K\n", term::frame(present, t, mode));
        std::thread::sleep(Duration::from_millis(60));
    }
    print!("\x1b[?25h");
}
