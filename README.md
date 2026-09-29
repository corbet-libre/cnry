# cnry

**Warrant canary: a signed, fresh statement that we have not been compelled.**

`cnry` publishes and checks a warrant canary. While a valid, fresh statement
exists, applications show it (in cmeet: a bird that flies). When the statement
stops being renewed, fails verification or goes stale, the canary is gone.

Status: name reserved, no implementation yet. Low priority.

## How it works

| Part | Design |
|---|---|
| Statement | "As of this date we have received no order to modify our software, hand over keys or data, or log member activity", plus the date |
| Freshness | Each statement carries a value nobody could know in advance (for example a recent public block hash), so statements cannot be signed ahead of time |
| Signing | Several signers; every one of them is required. Signing keys stay with the signers, never on a server |
| Renewal | Automatic and scheduled. Each renewal needs a short confirmation from every signer; if any confirmation is missing, renewal stops and the canary dies |
| Publication | Automatic, to several independent places, so the statement cannot be swapped out in one place unnoticed |
| Check | In the client: the signer keys are pinned in the application; valid signatures from all signers and an age within the allowed window mean the canary is alive |

The canary dies only by **not being renewed**. Nothing in our software ever
kills it actively: an automatic trigger (for example from a legal order entered
elsewhere) would be active disclosure, which a gag order can forbid.

## Boundaries

What it does:

- Builds, signs and publishes canary statements on a schedule.
- Verifies a statement in the client and answers: alive or gone.

What it never does:

- Never depends on or is triggered by cvld, cfrm, cmsg or clbs. It is independent of every other library.
- Never holds signing keys on a server.
- No own cryptographic primitives: established signature schemes only.

Warrant canaries are largely untested in court. They inform and deter; they are
not legal protection.

## License

Copyright 2026 Julian Y. Richard Corbet. Licensed under
[LGPL-3.0-only](LICENSES/LGPL-3.0-only.txt)
[WITH LGPL-3.0-linking-exception](LICENSES/LGPL-3.0-linking-exception.txt).
See [LICENSE.md](LICENSE.md).
