//! The `cnry/1` statement.

use crate::{SCHEMA, canon, key::SecretKey};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::{Duration, OffsetDateTime, format_description::well_known::Rfc3339};

/// Proof that the statement was made no earlier than a public event.
///
/// Kind `bitcoin-block`: a recent block's height, hash and time. The block
/// hash cannot be known before the block exists, so a statement carrying it
/// cannot have been signed earlier than the block.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Freshness {
    /// Always `bitcoin-block` in `cnry/1`.
    pub kind: String,
    /// Block height.
    pub height: u64,
    /// Block hash, 64 lowercase hex digits.
    pub hash: String,
    /// Block time, RFC 3339 UTC.
    pub time: String,
}

/// A parsed `cnry/1` statement (signature included, not yet verified).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statement {
    /// `cnry/1`.
    pub schema: String,
    /// The system the canary speaks for, e.g. `corbet.ch`.
    pub system: String,
    /// When the statement was signed, RFC 3339 UTC.
    pub issued: String,
    /// When the statement stops being valid, RFC 3339 UTC.
    pub expires: String,
    /// The statement text.
    pub statement: String,
    /// The freshness proof.
    pub freshness: Freshness,
    /// Fingerprint of the signing key, `ed25519:<hex>`.
    pub key: String,
    /// Base64url (no padding) Ed25519 signature over the canonical JSON of
    /// this object without `signature`.
    pub signature: String,
}

/// Parse an RFC 3339 timestamp that must be written in UTC with a `Z`.
pub fn parse_utc(text: &str) -> Option<OffsetDateTime> {
    if !text.ends_with('Z') {
        return None;
    }
    OffsetDateTime::parse(text, &Rfc3339).ok()
}

/// Format as RFC 3339 UTC with seconds precision.
pub fn format_utc(t: OffsetDateTime) -> String {
    let t = t
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .unwrap_or(t);
    t.format(&Rfc3339).unwrap_or_default()
}

impl Statement {
    /// Parse a statement from JSON text (strict: no unknown members).
    pub fn parse(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// The bytes the signature covers for the JSON object `doc`: its
    /// canonical form with the `signature` member removed.
    pub fn signing_bytes(doc: &Value) -> Result<Vec<u8>, canon::CanonError> {
        let mut doc = doc.clone();
        doc.as_object_mut()
            .ok_or(canon::CanonError("not an object"))?
            .remove("signature");
        Ok(canon::canonicalize(&doc)?.into_bytes())
    }

    /// Build and sign a statement. `issued` and `expires` are explicit; the
    /// caller decides them (there is no renewal logic anywhere in this crate).
    pub fn sign(
        secret: &SecretKey,
        system: &str,
        statement: &str,
        issued: OffsetDateTime,
        valid_for: Duration,
        freshness: Freshness,
    ) -> Result<Self, canon::CanonError> {
        let mut s = Statement {
            schema: SCHEMA.into(),
            system: system.into(),
            issued: format_utc(issued),
            expires: format_utc(issued + valid_for),
            statement: statement.into(),
            freshness,
            key: secret.public().fingerprint(),
            signature: String::new(),
        };
        let doc = serde_json::to_value(&s).map_err(|_| canon::CanonError("serialise"))?;
        s.signature = B64.encode(secret.0.sign(&Self::signing_bytes(&doc)?).to_bytes());
        Ok(s)
    }
}
