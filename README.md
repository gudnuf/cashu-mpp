# cashu-mpp

Spike: NUT-24 HTTP 402 + cashu, server-side validation in Rust.

## What this is

A demo server that exposes `GET /random?bits=N` and gates it behind a Cashu payment. Without an `X-Cashu` token, the server replies with `402 Payment Required` and a NUT-18 payment request in the `X-Cashu` response header. The client mints (or holds) ecash from the allowed mint, then retries the same URL with `X-Cashu: cashuB...`. On valid token, the server returns random bytes.

**Status:** v0.1 spike. Validation only — no `/melt` redemption. Tokens are checked (mint allowlist, unit, amount, signatures) but not spent.

**Spec source:** [NUT-24](https://github.com/cashubtc/nuts/blob/main/24.md). The "mpp" in the name is the operator's working title; NUT-24 is HTTP 402 + cashu, not Lightning multi-path payments.

## Hardcoded for the spike

| Field | Value |
|-------|-------|
| Price | 10 sats |
| Unit | `sat` |
| Allowed mint | `https://testnut.cashu.space` |
| Listen | `:3000` |

## Running

```
cargo run
```

In another shell:

```
curl -i localhost:3000/random?bits=128            # 402 + X-Cashu header
curl -i localhost:3000/random?bits=128 -H "X-Cashu: cashuB..."  # 200 + random hex
```

## Smoke test

See `examples/smoke.rs` — mints 10 sats against testnut.cashu.space via the `cdk` crate, then drives both legs of the flow.

## Out of scope for v0.1

- `/melt` redemption (server takes custody)
- NUT-10 P2PK + locktime bond mode
- agicash-rs as the paying client
- SDK extraction into a reusable receive crate

See `NOTES.md` for retro findings.
