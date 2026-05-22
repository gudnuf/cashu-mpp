# cashu-mpp

A verifier SDK for [Stripe MPP](https://mpp.dev) with cashu as the payment method. Drop it into any HTTP server, get 402-gated endpoints paid in cashu — validation only, no `/melt` redemption.

## What this is

[MPP](https://mpp.dev) (Machine Payments Protocol) is Stripe's HTTP 402-based payment framework: `WWW-Authenticate: Payment` on the challenge, `Authorization: Payment` on the retry, `Payment-Receipt` on the success. This SDK implements the wire format and ships a verifier for `method=cashu` — an unregistered extension that carries a NUT-18 payment request out and a cashuB token back.

You wire it into your axum / actix / hono / express / fastapi / whatever server, point it at an allowlisted Cashu mint, set a price, and your endpoint is gated. The SDK handles challenge HMAC binding, credential parsing, mint contact (NUT-07 checkstate), and receipt construction. The server stays stateless: the challenge id is `HMAC-SHA-256(secret, realm|method|intent|request|expires|digest|opaque)`, so there's no challenge table to maintain.

## Repo layout

```
cashu-mpp/
├── rust/                       # Rust workspace (this is the reference impl)
│   ├── cashu-mpp-core          # Wire format. No network, no cashu. Framework-agnostic.
│   ├── cashu-mpp-cashu         # Cashu method validator. Depends on core + cdk.
│   └── examples/random/        # Demo server: GET /random gated at 10 sat.
├── README.md
└── NOTES.md                    # Design retro.
```

Planned: `js/` (npm package), `py/` (FastAPI etc), `go/`. Same wire format across all; conformance tested with shared test vectors. See M2+ in NOTES.md.

## Using the Rust SDK

```rust
use std::time::Duration;
use cashu_mpp_cashu::{CashuMpp, Outcome};

// at startup:
let mpp = CashuMpp::builder()
    .realm("my-service")
    .price(10)                                       // sat
    .allowed_mint("https://testnut.cashu.space")
    .challenge_ttl(Duration::from_secs(300))
    .build()?;

// at the boundary (any framework — this is just http types):
let url = "/premium?id=42";
match mpp.authorize(&headers, url).await {
    Outcome::Authorized(payment) => {
        // do the work, attach payment.receipt_header_value() to the response
    }
    Outcome::NeedsPayment(challenge) => {
        // return 402 with WWW-Authenticate: <challenge.www_authenticate>
        // and application/problem+json body: <challenge.body>
    }
    Outcome::Rejected(problem) => {
        // return <problem.status> with application/problem+json body
    }
}
```

The SDK speaks `http::HeaderMap` and `http::StatusCode` — used by axum, actix, hyper, warp, reqwest. No framework lock-in.

## Running the demo

```
cd rust
cargo run -p random-server                     # terminal A
cargo run -p random-server --example smoke     # terminal B
```

The smoke test mints 10 sat against `testnut.cashu.space` via cdk, drives the full 402 → credential → 200 handshake, and asserts the `Payment-Receipt` header shape. Look for `[smoke] PASS`.

For a manual peek at the 402:

```
curl -i 'localhost:3000/random?bits=128'
```

## Design

| Decision | Choice | Why |
|----------|--------|-----|
| Challenge binding | HMAC-SHA-256 over `realm\|method\|intent\|request\|expires\|digest\|opaque` (U+007C pipe, empty string for absent slots) | Stateless server, matches mpp.dev spec text |
| Validation depth | NUT-07 `post_check_state` against the mint | Strong online "valid + unspent" signal; DLEQ deferred to v0.2 |
| Wire shape for `request` | JCS-canonicalized JSON with `amount`, `currency`, `mints[]`, `nut18` | Non-cashu clients can read the price; cashu clients deserialize the NUT-18 blob natively |
| Opaque binding | Server-side JCS-encoded URL path+query | Credential issued for one URL can't be replayed against another |
| Receipt reference | `hex(SHA-256(token))` | Non-secret correlation handle, doesn't leak the token itself |
| Method registry | `method="cashu"` (unregistered) | Stripe's registry has `tempo` and `stripe`; cashu is a third-party extension |

See `NOTES.md` for the full retro on what the spec is ambiguous about and what we picked.

## What's not here yet

- Replay protection beyond `expires` (spec calls for one-shot credentials)
- NUT-12 DLEQ offline verification (latency win for proofs that carry DLEQ data)
- Multi-method support on one endpoint (e.g. `tempo` + `cashu` advertised together)
- Receipt signing
- Non-Rust ports (planned as separate workspaces under `js/`, `py/`)
