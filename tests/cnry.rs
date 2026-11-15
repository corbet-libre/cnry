//! Format, verification and renderer tests.

use cnry::canon::canonicalize;
use cnry::statement::{Freshness, Statement, parse_utc};
use cnry::{PublicKey, Reason, SecretKey, Verdict, check, verify};
use serde_json::{Value, json};
use time::{Duration, OffsetDateTime};

fn secret() -> SecretKey {
    SecretKey::from_seed([7u8; 32])
}

fn issued() -> OffsetDateTime {
    parse_utc("2026-11-15T12:00:00Z").unwrap()
}

fn freshness() -> Freshness {
    Freshness {
        kind: "bitcoin-block".into(),
        height: 900_000,
        hash: "00000000000000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7".into(),
        time: "2026-11-15T11:50:00Z".into(),
    }
}

fn signed() -> Statement {
    Statement::sign(
        &secret(),
        "corbet.ch",
        "No order has been received.",
        issued(),
        Duration::days(30),
        freshness(),
    )
    .unwrap()
}

fn now() -> OffsetDateTime {
    issued() + Duration::days(1)
}

fn pubkey() -> PublicKey {
    secret().public()
}

fn mutate(f: impl FnOnce(&mut Value)) -> String {
    let mut v = serde_json::to_value(signed()).unwrap();
    f(&mut v);
    v.to_string()
}

#[test]
fn canonical_sorting_and_escapes_match_rfc8785() {
    // RFC 8785 section 3.2.3, "Sorting of Object Properties" (string members).
    let input: Value = serde_json::from_str(
        r#"{"\u20ac":"Euro Sign","\r":"Carriage Return","\ufb33":"Hebrew Letter Dalet With Dagesh","1":"One","\ud83d\ude00":"Emoji: Grinning Face","\u0080":"Control","\u00f6":"Latin Small Letter O With Diaeresis"}"#,
    )
    .unwrap();
    let expected = "{\"\\r\":\"Carriage Return\",\"1\":\"One\",\"\u{80}\":\"Control\",\"\u{f6}\":\"Latin Small Letter O With Diaeresis\",\"\u{20ac}\":\"Euro Sign\",\"\u{1f600}\":\"Emoji: Grinning Face\",\"\u{fb33}\":\"Hebrew Letter Dalet With Dagesh\"}";
    assert_eq!(canonicalize(&input).unwrap(), expected);
}

#[test]
fn canonical_whitespace_nesting_control_chars_and_integers() {
    let v = json!({"b": [1, -2, true, null, {"z": 0, "a": "x\u{1f}\"\\\n"}], "a": 18446744073709551615u64});
    assert_eq!(
        canonicalize(&v).unwrap(),
        r#"{"a":18446744073709551615,"b":[1,-2,true,null,{"a":"x\u001f\"\\\n","z":0}]}"#
    );
    assert!(canonicalize(&json!({"f": 1.5})).is_err());
}

#[test]
fn round_trip_is_present() {
    let json = serde_json::to_string(&signed()).unwrap();
    match verify(&json, &pubkey(), now()) {
        Verdict::Present(st) => assert_eq!(st.system, "corbet.ch"),
        Verdict::Absent => panic!("a fresh signed statement must be present"),
    }
}

#[test]
fn member_order_and_whitespace_do_not_matter() {
    let pretty = serde_json::to_string_pretty(&signed()).unwrap();
    assert!(matches!(
        verify(&pretty, &pubkey(), now()),
        Verdict::Present(_)
    ));
}

#[test]
fn tampering_with_any_field_is_absent() {
    let cases: [(&str, Value); 6] = [
        ("system", json!("evil.example")),
        ("statement", json!("Everything is fine.")),
        ("issued", json!("2026-11-15T12:00:01Z")),
        ("expires", json!("2030-01-01T00:00:00Z")),
        (
            "freshness",
            json!({"kind": "bitcoin-block", "height": 900001, "hash": "00000000000000000001a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f7", "time": "2026-11-15T11:50:00Z"}),
        ),
        ("signature", json!("AAAA")),
    ];
    for (field, value) in cases {
        let json = mutate(|v| v[field] = value);
        assert_eq!(verify(&json, &pubkey(), now()), Verdict::Absent, "{field}");
    }
    let extra = mutate(|v| v["extra"] = json!(1));
    assert_eq!(verify(&extra, &pubkey(), now()), Verdict::Absent);
}

#[test]
fn reasons_are_named_for_diagnostics() {
    let json = serde_json::to_string(&signed()).unwrap();
    assert_eq!(
        check(&json, &pubkey(), issued() + Duration::days(31)).unwrap_err(),
        Reason::Expired
    );
    assert_eq!(
        check(&json, &pubkey(), issued() - Duration::hours(1)).unwrap_err(),
        Reason::NotYetValid
    );
    assert_eq!(
        check(&mutate(|v| v["statement"] = json!("x")), &pubkey(), now()).unwrap_err(),
        Reason::BadSignature
    );
    assert_eq!(
        check("not json", &pubkey(), now()).unwrap_err(),
        Reason::Malformed
    );
    assert_eq!(
        check(&mutate(|v| v["schema"] = json!("cnry/2")), &pubkey(), now()).unwrap_err(),
        Reason::Schema
    );
    let other = SecretKey::from_seed([8u8; 32]).public();
    assert_eq!(check(&json, &other, now()).unwrap_err(), Reason::WrongKey);
}

#[test]
fn expiry_boundary() {
    let json = serde_json::to_string(&signed()).unwrap();
    let expires = parse_utc(&signed().expires).unwrap();
    assert!(matches!(
        verify(&json, &pubkey(), expires - Duration::seconds(1)),
        Verdict::Present(_)
    ));
    assert_eq!(verify(&json, &pubkey(), expires), Verdict::Absent);
}

#[test]
fn freshness_sanity() {
    let sign_with = |f: Freshness| {
        serde_json::to_string(
            &Statement::sign(&secret(), "corbet.ch", "x", issued(), Duration::days(30), f).unwrap(),
        )
        .unwrap()
    };
    let mut f = freshness();
    f.time = "2026-11-14T11:00:00Z".into(); // more than a day before issue
    assert_eq!(
        check(&sign_with(f), &pubkey(), now()).unwrap_err(),
        Reason::Freshness
    );
    let mut f = freshness();
    f.time = "2026-11-15T13:00:00Z".into(); // after issue
    assert_eq!(
        check(&sign_with(f), &pubkey(), now()).unwrap_err(),
        Reason::Freshness
    );
    let mut f = freshness();
    f.hash = "abc".into();
    assert_eq!(
        check(&sign_with(f), &pubkey(), now()).unwrap_err(),
        Reason::Freshness
    );
    let mut f = freshness();
    f.kind = "other".into();
    assert_eq!(
        check(&sign_with(f), &pubkey(), now()).unwrap_err(),
        Reason::Freshness
    );
}

#[test]
fn non_utc_timestamps_are_malformed() {
    let json = mutate(|v| v["expires"] = json!("2026-12-15T13:00:00+01:00"));
    assert_eq!(verify(&json, &pubkey(), now()), Verdict::Absent);
}

#[test]
fn key_text_forms_round_trip() {
    let k = secret();
    assert_eq!(SecretKey::parse(&k.to_text()).unwrap().public(), k.public());
    assert_eq!(PublicKey::parse(&k.public().to_text()).unwrap(), k.public());
    assert!(PublicKey::parse("ed25519pub:short").is_err());
    assert!(SecretKey::parse("ed25519pub:AAAA").is_err());
    assert_eq!(k.public().fingerprint().len(), "ed25519:".len() + 40);
}

/// The fixed vectors under tests/vectors are what the web component's tests
/// verify too. Ed25519 signatures are deterministic, so they must match what
/// this code produces; run with CNRY_BLESS=1 to rewrite them.
#[test]
fn vectors_match() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/vectors");
    let valid = serde_json::to_string_pretty(&signed()).unwrap() + "\n";
    let key = pubkey().to_text() + "\n";
    if std::env::var("CNRY_BLESS").is_ok() {
        std::fs::write(format!("{dir}/valid.json"), &valid).unwrap();
        std::fs::write(format!("{dir}/key.pub"), &key).unwrap();
    }
    assert_eq!(
        std::fs::read_to_string(format!("{dir}/valid.json")).unwrap(),
        valid
    );
    assert_eq!(
        std::fs::read_to_string(format!("{dir}/key.pub")).unwrap(),
        key
    );
}

#[test]
fn sprite_matches_web_component() {
    let js = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/web/cnry-canary.js"))
        .unwrap();
    let rows: Vec<&str> = js
        .lines()
        .filter_map(|l| {
            l.trim()
                .trim_end_matches(',')
                .strip_prefix('"')
                .and_then(|l| l.strip_suffix('"'))
        })
        .filter(|l| l.len() == 24 && l.chars().all(|c| c == '.' || c.is_ascii_alphabetic()))
        .collect();
    assert_eq!(rows, cnry::scene::SPRITE);
}

#[test]
fn terminal_frames_cover_both_states() {
    use cnry::term::{ColorMode, frame};
    let present = frame(true, 1.0, ColorMode::TrueColor);
    let absent = frame(false, 20.0, ColorMode::TrueColor);
    assert!(present.contains("38;2;"));
    assert_ne!(present, absent);
    assert!(frame(true, 1.0, ColorMode::Ansi256).contains("38;5;"));
    // 41 pixel rows -> 21 text rows
    assert_eq!(present.lines().count(), 21);
    // The empty swing rests: identical frames once settled.
    assert_eq!(absent, frame(false, 30.0, ColorMode::TrueColor));
    // The absent scene never contains the bird's beak colour.
    assert!(!absent.contains("240;160;48"));
    assert!(
        present.contains("240;160;48")
            || frame(true, 0.5, ColorMode::TrueColor).contains("240;160;48")
    );
}

/// The web verifier's own tests, when Node is installed (CI without Node skips).
#[test]
fn web_component_tests() {
    let root = env!("CARGO_MANIFEST_DIR");
    match std::process::Command::new("node")
        .args(["--test", "web/test.mjs"])
        .current_dir(root)
        .output()
    {
        Ok(out) => assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stdout)
        ),
        Err(_) => eprintln!("node not found: web tests skipped"),
    }
}
