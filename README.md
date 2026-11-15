# cnry

**Warrant canary: a signed, fresh statement that we have not been compelled.**

While a valid, unexpired statement exists the canary sits on its swing and
sings. When it is missing, expired, unverifiable or stale, the swing is empty.
The answer is present or absent, never anything in between, and nothing in
this project renews a statement or notifies anyone.

| Part | Where |
|---|---|
| Format `cnry/1` (draft) | [`docs/spec.md`](docs/spec.md) |
| Rust library: parse, canonicalise (RFC 8785), sign, verify | `src/` |
| CLI: `cnry keygen`, `pubkey`, `sign`, `verify` | `src/bin/cnry.rs` |
| Terminal renderer (half blocks, 24-bit or 256 colours) | `src/term.rs`, `examples/canary.rs` |
| Web component `<cnry-canary>` (canvas, birdsong, reduced motion) | `web/cnry-canary.js` |
| Small devices (ESP32, LED) | [`docs/small-devices.md`](docs/small-devices.md) |

## Use

```sh
cnry keygen ./canary.key                      # writes the key only to that path
cnry sign --key ./canary.key --system corbet.ch --statement text.txt --days 30 > canary.json
cnry verify --key ed25519pub:... canary.json  # PRESENT or ABSENT (exit 0 or 1)
cargo run --example canary -- --key ed25519pub:... canary.json
```

`sign` fetches a recent Bitcoin block (default `https://blockstream.info`,
change with `--api`) as the freshness proof, takes the lifetime from
`--days` (no default), and reads the key from the given file. Nothing is
generated or stored silently.

```html
<script type="module" src="/cnry-canary.js"></script>
<cnry-canary src="/.well-known/canary.json" key="ed25519pub:..."></cnry-canary>
```

The component verifies in the browser against the pinned `key`, uses WebCrypto
Ed25519 where available and otherwise the vendored
[noble-ed25519](web/vendor/noble-ed25519.js) (MIT, v2.3.0), and shows the
empty swing on any failure. Library users without the CLI build with
`default-features = false`.

## Tests

`cargo test` runs the canonicalisation vectors (RFC 8785), sign and verify
round trips, tamper, expiry and freshness cases, the sprite parity check
against the web component, and `node --test web/test.mjs` when Node is
installed (Rust-signed vectors verified by the web code, WebCrypto and the
vendored fallback).

Licence: LGPL-3.0-only WITH LGPL-3.0-linking-exception.
