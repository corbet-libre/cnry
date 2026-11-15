//! Verification. The public answer is two-valued; [`check`] additionally
//! names the first failing reason for diagnostics and tests, but a consumer
//! deciding what to show must use [`verify`] (present or absent, nothing in
//! between).

use crate::statement::{Statement, parse_utc};
use crate::{SCHEMA, key::PublicKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::Signature;
use serde_json::Value;
use time::{Duration, OffsetDateTime};

/// Tolerated clock difference between signer and verifier.
pub const SKEW: Duration = Duration::minutes(5);
/// A statement may be signed at most this long after the block it cites.
pub const MAX_PROOF_AGE: Duration = Duration::hours(24);

/// The one answer a consumer gets.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Verified, unexpired, fresh: the canary is on its swing.
    Present(Box<Statement>),
    /// Missing, malformed, unverifiable, expired or stale: the swing is empty.
    Absent,
}

/// First reason a statement is rejected (diagnostics only).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Not parseable as `cnry/1` JSON, or a timestamp is malformed.
    Malformed,
    /// Wrong schema identifier.
    Schema,
    /// The `key` fingerprint is not the pinned key's.
    WrongKey,
    /// The signature does not verify.
    BadSignature,
    /// `issued` lies in the future.
    NotYetValid,
    /// `expires` has passed (or precedes `issued`).
    Expired,
    /// The freshness proof is malformed or does not fit the issue time.
    Freshness,
}

/// Verify `json` against the pinned `key` at time `now`; return the statement
/// or the first reason it is rejected.
pub fn check(json: &str, key: &PublicKey, now: OffsetDateTime) -> Result<Statement, Reason> {
    let doc: Value = serde_json::from_str(json).map_err(|_| Reason::Malformed)?;
    let st = Statement::parse(json).map_err(|_| Reason::Malformed)?;
    if st.schema != SCHEMA {
        return Err(Reason::Schema);
    }
    if st.key != key.fingerprint() {
        return Err(Reason::WrongKey);
    }
    let bytes = Statement::signing_bytes(&doc).map_err(|_| Reason::Malformed)?;
    let sig = B64
        .decode(&st.signature)
        .map_err(|_| Reason::BadSignature)?;
    let sig = Signature::from_slice(&sig).map_err(|_| Reason::BadSignature)?;
    key.0
        .verify_strict(&bytes, &sig)
        .map_err(|_| Reason::BadSignature)?;

    let issued = parse_utc(&st.issued).ok_or(Reason::Malformed)?;
    let expires = parse_utc(&st.expires).ok_or(Reason::Malformed)?;
    if issued > now + SKEW {
        return Err(Reason::NotYetValid);
    }
    if expires <= issued || expires <= now {
        return Err(Reason::Expired);
    }
    check_freshness(&st, issued, now)?;
    Ok(st)
}

fn check_freshness(
    st: &Statement,
    issued: OffsetDateTime,
    now: OffsetDateTime,
) -> Result<(), Reason> {
    let f = &st.freshness;
    let hash_ok = f.hash.len() == 64
        && f.hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if f.kind != "bitcoin-block" || f.height == 0 || !hash_ok {
        return Err(Reason::Freshness);
    }
    let block = parse_utc(&f.time).ok_or(Reason::Freshness)?;
    // The block must exist before the statement was signed (and before now),
    // and not be so old that the proof says nothing about the signing time.
    if block > issued + SKEW || block > now + SKEW || issued - block > MAX_PROOF_AGE {
        return Err(Reason::Freshness);
    }
    Ok(())
}

/// The two-valued verdict: [`Verdict::Present`] only if [`check`] passes.
pub fn verify(json: &str, key: &PublicKey, now: OffsetDateTime) -> Verdict {
    match check(json, key, now) {
        Ok(st) => Verdict::Present(Box::new(st)),
        Err(_) => Verdict::Absent,
    }
}
