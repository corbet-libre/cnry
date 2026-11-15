//! `cnry`: the signing and verifying command line.
//!
//! * `cnry keygen <path>`: write a new secret key to `<path>` (never over an
//!   existing file) and print its public key and fingerprint.
//! * `cnry pubkey <keyfile>`: print the public key of a secret key file.
//! * `cnry sign --key F --system S --statement F|- --days N [--freshness-file F]`:
//!   fetch a recent Bitcoin block, sign, print the statement JSON.
//! * `cnry verify --key ed25519pub:... [FILE|-]`: print PRESENT or ABSENT;
//!   exit 0 when present, 1 when absent.
//!
//! Keys are only ever read from, or written to, paths named on the command
//! line. Nothing here renews anything.

use cnry::statement::{Freshness, Statement, format_utc};
use cnry::{PublicKey, SecretKey, Verdict, verify};
use std::io::{Read, Write};
use std::process::ExitCode;
use time::{Duration, OffsetDateTime};

const DEFAULT_API: &str = "https://blockstream.info";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("keygen") => keygen(&args[1..]),
        Some("pubkey") => pubkey(&args[1..]),
        Some("sign") => sign(&args[1..]),
        Some("verify") => return verify_cmd(&args[1..]),
        _ => Err("usage: cnry keygen <path> | pubkey <keyfile> | sign --key F --system S --statement F|- --days N [--freshness-file F] [--api URL] | verify --key ed25519pub:... [FILE|-]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("cnry: {e}");
            ExitCode::from(2)
        }
    }
}

type Res<T> = Result<T, String>;

fn opt<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .map(String::as_str)
}

fn read_input(path: &str) -> Res<String> {
    let mut s = String::new();
    if path == "-" {
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| e.to_string())?;
    } else {
        s = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
    }
    Ok(s)
}

fn keygen(args: &[String]) -> Res<()> {
    let path = args.first().ok_or("keygen needs an explicit output path")?;
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|e| e.to_string())?;
    let key = SecretKey::from_seed(seed);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut opts, 0o600);
    let mut f = opts.open(path).map_err(|e| format!("{path}: {e}"))?;
    writeln!(f, "{}", key.to_text()).map_err(|e| e.to_string())?;
    println!("{}\n{}", key.public().to_text(), key.public().fingerprint());
    Ok(())
}

fn load_secret(path: &str) -> Res<SecretKey> {
    SecretKey::parse(&read_input(path)?).map_err(|e| format!("{path}: {e}"))
}

fn pubkey(args: &[String]) -> Res<()> {
    let key = load_secret(args.first().ok_or("pubkey needs a key file")?)?.public();
    println!("{}\n{}", key.to_text(), key.fingerprint());
    Ok(())
}

fn get(url: &str) -> Res<String> {
    ureq::get(url)
        .call()
        .map_err(|e| format!("{url}: {e}"))?
        .body_mut()
        .read_to_string()
        .map_err(|e| format!("{url}: {e}"))
}

/// A recent block from an Esplora-style API (`/api/blocks/tip/hash`, `/api/block/<hash>`).
fn fetch_freshness(api: &str) -> Res<Freshness> {
    let hash = get(&format!("{api}/api/blocks/tip/hash"))?
        .trim()
        .to_string();
    let block: serde_json::Value = serde_json::from_str(&get(&format!("{api}/api/block/{hash}"))?)
        .map_err(|e| e.to_string())?;
    let height = block["height"].as_u64().ok_or("block has no height")?;
    let ts = block["timestamp"]
        .as_i64()
        .ok_or("block has no timestamp")?;
    let time = OffsetDateTime::from_unix_timestamp(ts).map_err(|e| e.to_string())?;
    Ok(Freshness {
        kind: "bitcoin-block".into(),
        height,
        hash,
        time: format_utc(time),
    })
}

fn sign(args: &[String]) -> Res<()> {
    let key = load_secret(opt(args, "--key").ok_or("--key <secret key file> is required")?)?;
    let system = opt(args, "--system").ok_or("--system is required")?;
    let text = read_input(opt(args, "--statement").ok_or("--statement <file|-> is required")?)?;
    // No default lifetime: the signer states it every time.
    let days: i64 = opt(args, "--days")
        .ok_or("--days is required")?
        .parse()
        .map_err(|_| "--days must be a number")?;
    if !(1..=366).contains(&days) {
        return Err("--days must be between 1 and 366".into());
    }
    let freshness = match opt(args, "--freshness-file") {
        Some(p) => serde_json::from_str(&read_input(p)?).map_err(|e| format!("{p}: {e}"))?,
        None => fetch_freshness(
            opt(args, "--api")
                .unwrap_or(DEFAULT_API)
                .trim_end_matches('/'),
        )?,
    };
    let st = Statement::sign(
        &key,
        system,
        text.trim(),
        OffsetDateTime::now_utc(),
        Duration::days(days),
        freshness,
    )
    .map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&st).map_err(|e| e.to_string())?
    );
    Ok(())
}

fn verify_cmd(args: &[String]) -> ExitCode {
    let run = || -> Res<Verdict> {
        let key = PublicKey::parse(opt(args, "--key").ok_or("--key ed25519pub:... is required")?)
            .map_err(|e| e.to_string())?;
        let path = args
            .iter()
            .rev()
            .find(|a| !a.starts_with("--") && !a.starts_with("ed25519pub:"))
            .map_or("-", String::as_str);
        // An unreadable statement is the absent canary, not an error.
        Ok(match read_input(path) {
            Ok(json) => verify(&json, &key, OffsetDateTime::now_utc()),
            Err(_) => Verdict::Absent,
        })
    };
    match run() {
        Ok(Verdict::Present(st)) => {
            println!("PRESENT {} expires {}", st.system, st.expires);
            ExitCode::SUCCESS
        }
        Ok(Verdict::Absent) => {
            println!("ABSENT");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("cnry: {e}");
            ExitCode::from(2)
        }
    }
}
