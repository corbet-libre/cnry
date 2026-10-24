# Agent instructions

Write all code comments and documentation in English.

## Product boundary

- Warrant canary: signed, fresh statements that we have not been compelled; the canary dies by not being renewed.
- Builds, signs and publishes statements on a schedule; verifies them in the client (alive or gone).
- Renewal is automatic but requires a confirmation from every signer each period.
- Independent of every other library: never depends on or is triggered by cvld, cfrm, cmsg or clbs.
- Never holds signing keys on a server; never kills the canary actively.
- No own cryptographic primitives: established signature schemes only.
- This crate is LGPL-3.0-only WITH LGPL-3.0-linking-exception. Do not add implementation code available only under the full GPL or AGPL.

## Quality boundary

- `cargo fmt --check`, `cargo clippy --all-targets` (no warnings),
  `cargo test` — all green before every commit. No local
  builds; use GHA, Crow as fallback.
