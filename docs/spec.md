# cnry/1: the warrant-canary statement

Status: draft, to be agreed before any release. English only.

A canary is a statement that is only true while someone keeps signing it. It
is **absent** the moment it is missing, expired, unverifiable or stale. There
is no in-between state, no warning state, and nothing that renews it on its
own.

## Document

One JSON object (UTF-8). All members are required; unknown members are
rejected (they would be unsigned-looking but signed, which confuses readers).

| Member | Type | Meaning |
|---|---|---|
| `schema` | string | Exactly `cnry/1`. |
| `system` | string | The system the canary speaks for, e.g. `corbet.ch`. |
| `issued` | string | RFC 3339 UTC (`...Z`), when it was signed. |
| `expires` | string | RFC 3339 UTC (`...Z`), after which it is void. Must be after `issued`. |
| `statement` | string | The text being attested. |
| `freshness` | object | Proof the statement was signed no earlier than a public event (below). |
| `key` | string | Fingerprint of the signing key: `ed25519:` + first 20 bytes of SHA-256(raw public key) as 40 lowercase hex digits. |
| `signature` | string | Base64url (no padding) Ed25519 signature, 64 bytes. |

### Freshness (`bitcoin-block`)

| Member | Type | Meaning |
|---|---|---|
| `kind` | string | Exactly `bitcoin-block`. |
| `height` | integer | Block height, at least 1. |
| `hash` | string | Block hash, 64 lowercase hex digits. |
| `time` | string | Block time, RFC 3339 UTC. |

A block hash cannot be known before the block exists, so a statement that
cites it was signed after that block. Rules: the block time is not after
`issued` (5 minutes of clock skew allowed) and `issued` is at most 24 hours
after the block time. A verifier without chain access checks only these
rules; it does not prove the block is real. A verifier with chain access may
additionally compare the hash.

## Signature

1. Remove `signature` from the object.
2. Canonicalise with RFC 8785 (JCS). Only objects, arrays, strings, booleans,
   null and integers occur; a non-integer number is invalid.
3. Sign the UTF-8 bytes with Ed25519 (RFC 8032). Verifiers should use the
   strict (non-malleable) check.

## Keys

The verifier is given the public key out of band and **pins** it. A statement
never carries its own key, only the fingerprint, which must match the pinned
key. Text forms: `ed25519pub:<base64url of the 32-byte key>`,
`ed25519sec:<base64url of the 32-byte seed>`.

## Verification (the whole algorithm)

The canary is present iff all hold at the verifier's current time `now`:

1. The document parses with exactly the members above and `schema` is `cnry/1`.
2. `key` equals the fingerprint of the pinned key.
3. The signature verifies.
4. `issued` is not later than `now` + 5 minutes.
5. `expires` is after `issued` and after `now`.
6. The freshness rules hold.

Anything else, including a failed fetch, is absent. A page open for a long
time must re-evaluate `expires` against the clock, not only at load.

## Publication

* `/.well-known/canary.json` per system (the web component's default `src`).
* Retained MQTT message on `public/canary/<system>` carrying the same JSON.
* History and an Atom feed are published by the operator; they are not part
  of verification.

## What the format does not do

It does not renew itself, notify anyone, or hold keys on a server. Who signs
renewals, and how often, is an operational decision outside this document.
