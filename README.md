# cashu-mpp

Spike: [Stripe MPP](https://mpp.dev) wire format with cashu as the payment method. Server-side validation in Rust. No `/melt` redemption.

## What this is

A demo server that exposes `GET /random?bits=N` and gates it behind a Cashu payment, using Stripe's Machine Payments Protocol (MPP) as the HTTP-level handshake. The "cashu" method itself is **not on Stripe's registered method list** — this spike implements it as an unregistered extension to validate the wire-format end to end.

The flow:

1. Client `GET /random`.
2. Server replies `402 Payment Required` with `WWW-Authenticate: Payment ...` carrying an HMAC-bound challenge and a NUT-18 payment request.
3. Client mints 10 sat from the allowed mint and builds an `Authorization: Payment <base64url(JSON)>` credential.
4. Client retries. Server verifies the HMAC binding, decodes the `cashuB` token, runs NUT-07 `post_check_state` against the mint, and on success returns the resource plus a `Payment-Receipt` header.

Validation only — tokens stay unspent at the mint after the server hands back the resource.

## Hardcoded for the spike

| Field | Value |
|-------|-------|
| Price | 10 sat |
| Unit | `sat` |
| Allowed mint | `https://testnut.cashu.space` |
| Listen | `0.0.0.0:3000` |
| Realm | `cashu-mpp` |
| Method | `cashu` (unregistered) |
| Challenge TTL | 5 min |
| Challenge binding | HMAC-SHA-256, key generated at server startup |

## Running

Terminal A:

```
cargo run
```

Terminal B:

```
cargo run --example smoke
```

The smoke test mints from `testnut.cashu.space` via the `cdk` crate, drives the full 402 → credential → 200 handshake, and asserts the receipt shape.

For a manual peek at the 402:

```
curl -i 'localhost:3000/random?bits=128'
```

## Layout

| File | Purpose |
|------|---------|
| `src/main.rs` | axum server, request handler, challenge / credential / receipt construction |
| `src/mpp.rs` | MPP types: `Challenge`, `Credential`, `Receipt`. HMAC binding, JCS encoding, `WWW-Authenticate` parser. Five unit tests. |
| `examples/smoke.rs` | End-to-end client: mint via `cdk`, parse 402, build credential, retry, verify receipt. |
| `NOTES.md` | Design retro: spec ambiguities and the calls we made under them. |

## Out of scope

- `/melt` redemption (server takes custody of the ecash). Use case is closer to "fiat-equivalent payment" than the validate-only "soft commitment" the spike implements.
- NUT-10 P2PK + locktime "bond mode" — payer locks ecash to themselves with a future locktime. Sketched in NOTES.md.
- Replay protection beyond `expires` on the challenge. Spec calls for one-shot credentials; we accept the same credential repeatedly while unexpired.
- A second payment method on the same endpoint (Stripe SPT, Tempo, ...).
- Receipt signing.
- SDK extraction into a reusable receive crate.

See `NOTES.md` for the full retro.
