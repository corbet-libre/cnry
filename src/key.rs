//! Keys and their text forms.
//!
//! * secret key file / string: `ed25519sec:<base64url of the 32-byte seed>`
//! * public key string:        `ed25519pub:<base64url of the 32-byte key>`
//! * fingerprint (statement):  `ed25519:<first 20 bytes of SHA-256(public key), lowercase hex>`
//!
//! A verifier is always given the public key out of band (pinned); the
//! statement only names it by fingerprint, so a statement can never introduce
//! its own key.

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD as B64};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use std::fmt;

/// A key string that does not parse.
#[derive(Debug, PartialEq, Eq)]
pub struct KeyError;

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("malformed key")
    }
}

impl std::error::Error for KeyError {}

/// A pinned Ed25519 public key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(crate) VerifyingKey);

/// An Ed25519 secret key (seed). Only the signer ever holds one.
pub struct SecretKey(pub(crate) SigningKey);

fn decode32(rest: &str) -> Result<[u8; 32], KeyError> {
    let bytes = B64.decode(rest.trim()).map_err(|_| KeyError)?;
    bytes.try_into().map_err(|_| KeyError)
}

impl PublicKey {
    /// Parse `ed25519pub:<base64url>`.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let rest = text.trim().strip_prefix("ed25519pub:").ok_or(KeyError)?;
        VerifyingKey::from_bytes(&decode32(rest)?)
            .map(Self)
            .map_err(|_| KeyError)
    }

    /// The text form, `ed25519pub:<base64url>`.
    pub fn to_text(&self) -> String {
        format!("ed25519pub:{}", B64.encode(self.0.to_bytes()))
    }

    /// The fingerprint a statement carries in its `key` field.
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.0.to_bytes());
        let hex: String = digest[..20].iter().map(|b| format!("{b:02x}")).collect();
        format!("ed25519:{hex}")
    }
}

impl SecretKey {
    /// Build a key from 32 seed bytes (the CLI draws them from the OS).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self(SigningKey::from_bytes(&seed))
    }

    /// Parse `ed25519sec:<base64url>`.
    pub fn parse(text: &str) -> Result<Self, KeyError> {
        let rest = text.trim().strip_prefix("ed25519sec:").ok_or(KeyError)?;
        Ok(Self::from_seed(decode32(rest)?))
    }

    /// The text form, `ed25519sec:<base64url>`.
    pub fn to_text(&self) -> String {
        format!("ed25519sec:{}", B64.encode(self.0.to_bytes()))
    }

    /// The matching public key.
    pub fn public(&self) -> PublicKey {
        PublicKey(self.0.verifying_key())
    }
}
