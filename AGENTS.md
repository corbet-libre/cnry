# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Warrant canary: signed, fresh statements that we have not been compelled; the canary dies by not being renewed.
- Format `cnry/1`, a signing CLI for the inner circle, verifiers (Rust, web) and renderers (terminal, web, small devices); verifies in the client (present or absent).
- No automatic renewal anywhere: a statement is signed by hand with an explicit key file and an explicit lifetime.
- Independent of every other library: never depends on or is triggered by cvld, cfrm, cmsg or clbs.
- Never holds signing keys on a server; never kills the canary actively.
- No own cryptographic primitives: established signature schemes only (Ed25519 via ed25519-dalek, WebCrypto, vendored noble-ed25519).
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local
  builds; use GHA, Crow as fallback.
