//! Warrant canary: signed, fresh statements that we have not been compelled.
//!
//! The format is `cnry/1` (see `docs/spec.md`). A statement is a JSON object
//! signed with Ed25519 over its RFC 8785 canonical form. Verification has
//! exactly two outcomes: the canary is [`Verdict::Present`] or it is
//! [`Verdict::Absent`]. Nothing in this crate renews, extends or signs on its
//! own; signing is an explicit act with an explicit key file.
#![forbid(unsafe_code)]

pub mod canon;
pub mod key;
pub mod scene;
pub mod statement;
pub mod term;
pub mod verify;

pub use key::{PublicKey, SecretKey};
pub use statement::{Freshness, Statement};
pub use verify::{Reason, Verdict, check, verify};

/// The schema identifier of the format this crate reads and writes.
pub const SCHEMA: &str = "cnry/1";
