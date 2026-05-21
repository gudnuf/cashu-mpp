# NOTES — cashu-mpp retro

Captured during the spike. Not a polished doc.

## v0.2: Stripe MPP wire format (2026-05-21)

After v0.1 shipped, operator clarified that "mpp" in the project name refers to **Stripe's Machine Payments Protocol** (`https://mpp.dev`), not NUT-24 or Lightning multi-path payments. v0.1 used NUT-24's `X-Cashu` header pattern. v0.2 rewires to MPP framing with `cashu` as an *unregistered* payment method.

**Wire shape v0.2 emits:**

```
HTTP/1.1 402 Payment Required
Content-Type: application/problem+json
Cache-Control: no-store
WWW-Authenticate: Payment id="<HMAC>", realm="cashu-mpp",
                  method="cashu", intent="charge",
                  request="<b64url(JCS)>", expires="<RFC3339>",
                  opaque="<b64url(JCS)>"

{ "type": "https://paymentauth.org/problems/payment-required",
  "title": "Payment Required", "status": 402, "detail": "...",
  "challengeId": "<HMAC>" }
```

Retry:
```
GET /random?bits=128
Authorization: Payment <b64url({
  "challenge": { realm, method, intent, request, expires, opaque },
  "id": "<HMAC echoed>",
  "source": "anonymous",
  "payload": { "token": "cashuB..." }
})>
```

Success:
```
HTTP/1.1 200 OK
Payment-Receipt: <b64url({
  "challengeId", "method": "cashu", "reference": "<sha256(token) hex>",
  "settlement": { "amount", "currency" },
  "status": "success", "timestamp": "<RFC3339>"
})>
```

**Design calls made under spec ambiguity:**

- **HMAC algorithm + canonical input.** The spec says challenges are bound through `realm | method | intent | request | expires | digest | opaque` with "empty string for absent slot." That phrasing rules out JCS-of-an-object (JCS would just omit absent fields) and points at fixed-position concat. Picked literal U+007C pipe bytes as the separator, HMAC-SHA-256 as the hash, base64url-no-pad as the id encoding. Stateless server design — no challenge table, the HMAC *is* the challenge id.
- **Cashu as unregistered method.** Used `method="cashu"`. Stripe's registry has `tempo` and `stripe`; cashu isn't there. No interop with Stripe-side verifiers is claimed.
- **Request blob shape for `method="cashu"`.** JCS-canonicalized JSON with `amount` (decimal string), `currency` (`"sat"`), `mints` (string array), and `nut18` (full creqA payment request). The first three fields let a non-cashu client surface a price; the `nut18` blob lets a cashu-aware client deserialize natively without parsing our extension.
- **Opaque field bound to request URL.** JCS of `{"url": "/random?bits=N"}`. Prevents a client from retrying with the credential at a different endpoint than the one that issued the 402. The HMAC binding already locks all other parameters; opaque is the spec-defined hook to bind transport-level context too.
- **Source = "anonymous".** Unlocked cashu tokens have no payer identity to assert. When v0.x adds P2PK bond mode, `source` becomes the payer's pubkey.
- **Receipt reference = `hex(SHA-256(token))`.** No on-chain hash; this is a correlation handle the receipt-holder can verify against the token they sent. Doesn't leak the token itself.
- **Verification failure → 402, malformed → 400.** Per spec problem types: a present-but-invalid credential returns 402 with `type=…/verification-failed`. A garbled header returns 400 with `type=…/malformed-credential`. A request-level error (bits out of range) is 400 with `type=…/bad-request`.

**What's still spec-shaped but unimplemented in v0.2:**

- Replay protection beyond `expires`. The spec says "Each credential is valid for exactly one request"; we don't track used credentials. A client could retry indefinitely while the challenge is unexpired. The natural fix is an in-memory LRU of `(challenge_id, sha256(token))` pairs — a few lines, but adds state to a deliberately stateless server. Deferred.
- Multiple methods on the same endpoint. Spec example shows `tempo` and `stripe` advertised together via two `WWW-Authenticate: Payment` headers. We emit one. Adding Stripe SPT or any other method would require a second method-specific module and a chooser in the handler.
- Receipt signing. Spec doesn't mandate it, but a real deployment would HMAC the receipt under a server key so receipt-holders can prove provenance. Our receipt is plain base64url JSON.

**Smoke transcript v0.2 (2026-05-21):**

```
[smoke] step 1: build in-memory wallet against https://testnut.cashu.space
[smoke] step 2: mint 10 sat against testnut (auto-settle)
[smoke]   minted 10 sat across 7 proof(s)
[smoke]   token = cashuBo2FteBtodHRwczovL3Rlc3RudXQuY2FzaH...  (2134 chars)
[smoke] step 3: GET http://127.0.0.1:3000/random?bits=128 (no auth, expect 402)
[smoke]   402 ok; problem type = https://paymentauth.org/problems/payment-required
[smoke] step 4: parse WWW-Authenticate + Cashu request blob
[smoke]   challenge id=x5PMKR0Z9rhQP31F amount=10 mints=["https://testnut.cashu.space"]
[smoke]   server nut18 = creqApmFp9mFhCmF1Y3NhdGF
[smoke] step 5: build credential and retry
[smoke]   200 ok; receipt method=cashu status=success settled=10sat timestamp=2026-05-21T22:55:09.067795+00:00
[smoke]   reference (sha256 of token, hex) = 342e3edac9c419e8271bba77db81cd8b0ad1d1db411d49b36614818e9e6dfa32
[smoke]   random_hex = af03e07999f33e5523368d52fe1e8170

[smoke] PASS
```

Five unit tests in `src/mpp.rs` cover challenge-id round-trip, tamper detection, empty-slot equivalence, credential auth-header round-trip, WWW-Authenticate parsing, and JCS base64url round-trip.

---

# v0.1 retro (preserved below — NUT-24 framing, superseded by v0.2)

## CDK survey

CDK 0.16.0 + cashu 0.16.0 cover everything v0.1 needs. Server pulls cdk with `default-features = false, features = ["wallet"]` (avoids cdk-signatory's `protoc` build dep).

**NUT-18 encode/decode (creqA):**
- `cdk::nuts::nut18::{PaymentRequest, PaymentRequestBuilder, Transport, TransportType}`
- `PaymentRequest::builder().amount(a).unit(u).add_mint(m).build()` → struct
- `Display` impl writes CBOR + base64url with `creqA` prefix
- `FromStr` decodes both CREQ-A (CBOR) and CREQ-B (bech32m, NUT-26)

**Token (cashuB) decode:**
- `cdk::nuts::nut00::token::Token::from_str("cashuB...")` → `Token::TokenV4(_) | Token::TokenV3(_)`
- Token methods: `unit()`, `mint_url()`, `proofs(&[KeySetInfo])`, `value()`, `memo()`, `token_secrets()`, `spending_conditions()`
- `proofs()` needs mint keyset info to expand the short keyset IDs in V4 tokens to full IDs

**Mint contact (server-side, no wallet needed):**
- `cdk::wallet::mint_connector::http_client::HttpClient::new(mint_url, None)` is the entry point
- Implements `MintConnector` trait with `get_mint_keysets()` (NUT-02) and `post_check_state(CheckStateRequest)` (NUT-07)
- This is what the v0.1 server uses to (a) fetch keysets for `Token::proofs()` and (b) ask the mint whether each proof is unspent

**Signature validation options:**
- NUT-07 `post_check_state` — mint declares each proof `Unspent | Pending | Spent | Reserved | PendingSpent`. Strong online "this is a real, currently-valid proof at this mint" signal.
- NUT-12 `Proof::verify_dleq(mint_pubkey)` — offline DLEQ verification. Only works if the proof carries DLEQ data. Needs mint pubkey for the proof's amount (from keyset).
- `dhke::verify_message(secret_key, ...)` is mint-private and not usable by a third-party validator.

**v0.1 plan:** use NUT-07 `post_check_state` as the canonical "valid" signal. Mint allowlist + unit + amount checks happen on the token struct before any network call. DLEQ verify is a v0.2+ option (offline-validation path) — punted to keep the surface small.

## Spec ambiguities

- **"signatures valid"** in the operator's brief is the slippery phrase. Three different things one might mean by it:
  1. The mint accepts the proofs as unspent (NUT-07). What v0.1 does.
  2. The proof carries a DLEQ proof that lets a third party verify the mint signed it without trusting the mint (NUT-12). Punted.
  3. The mint signed it, period — but verifying that needs the mint's secret key, which only the mint has. Not third-party-checkable without DLEQ.
  v0.1 picks (1). It does not prove the mint signed the proofs — it proves the mint currently treats them as live ecash. For a non-redeeming receiver this is the most useful single signal.

- **NUT-24 has the wire format but no semantics for "what does 'paid' mean"** if the receiver never melts. NUT-07 + mint allowlist + amount check is the convention this server adopts; nothing in the spec says exactly that.

- The cdk `Token::proofs(&KeySetInfo[])` API rejects proofs whose short keyset ID does not match any returned keyset. So if the mint rotates keysets between the client's mint operation and the server's check, validation fails — surface-level "token bad" even though it was correctly signed. Not addressed in v0.1.

- The X-Cashu request-header value is the full `cashuB...` token. At 10 sats, testnut returned 7 proofs and a 2134-char token. Real deployments with many proofs will run into HTTP header size limits (4–8 KB typical) — at some amount/denomination mix, this scheme silently fails. NUT-24 doesn't address this; the spec writers presumably expect short tokens.

## Smoke test transcript

Run: terminal A `cargo run`; terminal B `cargo run --example smoke`. Captured 2026-05-21.

```
[smoke] step 1: build in-memory wallet against https://testnut.cashu.space
[smoke] step 2: request 10-sat mint quote
[smoke]   quote_id=1eV18nfoZobuqg77IhOf180RkpuF2jim-2akZmyS
[smoke] step 3: wait for testnut to auto-settle (faucet style)
[smoke]   quote paid
[smoke] step 4: mint proofs
[smoke]   minted 10 sat across 7 proof(s)
[smoke] step 5: encode cashuB token
[smoke]   token = cashuBo2FteBtodHRwczovL3Rlc3RudXQuY2FzaH...  (2134 chars)
[smoke] step 6: GET http://127.0.0.1:3000/random?bits=128 (no token, expect 402)
[smoke]   402 ok; X-Cashu starts with: creqApmFp9mFhCmF1Y3NhdGF
[smoke] step 7: GET http://127.0.0.1:3000/random?bits=128 with X-Cashu (expect 200)
[smoke]   200 ok; amount_paid=10 proofs_checked=7 random_hex=a42052b2190a4ffb879334b40b61e4c6

[smoke] PASS
```

Negative paths (curl, no token math):

```
$ curl -i 'localhost:3000/random?bits=64' -H 'X-Cashu: notatoken'
HTTP/1.1 400 Bad Request
{"error":"decode token: Unsupported token"}

$ curl -i 'localhost:3000/random?bits=64' -H 'X-Cashu: cashuB!!!'
HTTP/1.1 400 Bad Request
{"error":"decode token: Invalid byte 33, offset 0."}

$ curl -i 'localhost:3000/random?bits=0'
HTTP/1.1 400 Bad Request
{"error":"bits must be 1..=4096"}
```

## SDK extraction sketch

A reusable `cashu-receive` crate could expose roughly:

```rust
pub struct Receiver { /* mint allowlist, default unit, ... */ }

pub struct PaymentRequirements {
    pub price: Amount,
    pub unit: CurrencyUnit,
    pub mints: Vec<MintUrl>,
    pub description: Option<String>,
    pub nut10: Option<Nut10SecretRequest>,
    pub single_use: bool,
}

impl Receiver {
    pub fn build_payment_request(&self, req: &PaymentRequirements) -> String; // returns creqA...
    pub async fn validate(&self, token_str: &str, req: &PaymentRequirements) -> Result<Validated, RejectReason>;
}

pub struct Validated {
    pub amount: Amount,
    pub mint: MintUrl,
    pub proofs: Proofs,
    pub dleq_verified: bool, // true if any proof carried DLEQ that checked out
}
```

The split that matters: keep `Receiver` HTTP-framework-agnostic. Provide thin adapters elsewhere (axum extractor, tower middleware, actix guard) that read `X-Cashu` and call `Receiver::validate`. Adapters live outside the core to avoid forcing a web framework on consumers who want CLI / non-HTTP receive flows (mqtt, websocket, etc).

Two policies for `Validated`:
- **Validate-only** (this spike) — `Validated` holds the proofs, server returns service, never touches `/melt`. The payer's ecash stays unspent at the mint.
- **Take custody** — receiver swaps the proofs immediately at the mint (NUT-03 swap or NUT-05 melt). Either keep as the receiver's own ecash, or melt to a Lightning destination. Requires the receiver to hold a wallet, which the spike consciously avoided.

A v0.2 SDK would distinguish these as two methods on `Receiver` or a separate `CustodialReceiver` type. The validate-only path is what 402-style "pay-to-read" / "pay-to-call" services want.

## NUT-10 bond mode estimate

"Bond mode" = the payer locks the ecash to themselves (P2PK to their own pubkey) with a future locktime, then hands it over. The receiver holds an unspendable token until the locktime expires, at which point the payer can reclaim it. The server uses receipt of the bond as a soft commitment — strong signal of buyer skin-in-the-game, without taking custody.

What v0.2 needs:

1. Server builds the NUT-18 `nut10` field as `Nut10SecretRequest { kind: P2PK, data: client_pubkey, tags: [["locktime", "<unix>"], ["refund", "<client_pubkey>"]] }`. The client populates `data` with its own pubkey by deriving from the request? Actually no — the payer's pubkey isn't known to the receiver in advance. Either:
   - Receiver leaves `data` empty/templated and trusts the client to fill it in correctly (and verifies via decoded token).
   - Receiver does a quick handshake (separate endpoint) to get the client's pubkey first, then issues a tailored payment request.
   The spec is ambiguous here. The handshake path is more honest.

2. Server validation on the inbound token: token proofs must carry P2PK spending conditions where `pubkeys == [<payer_pubkey>]`, `locktime >= now + min_bond_window`, and `refund == [<payer_pubkey>]`. cdk's `Token::spending_conditions()` + `cdk::nuts::nut11::SpendingConditions::P2PKConditions` decode this.

3. The "bond" never gets redeemed. After locktime, the payer can claim it back via NUT-11 refund path. Receiver does nothing.

Effort estimate: ~1 day of work assuming a brainstorm session to settle the handshake-vs-template question first. Most of the code is decoding NUT-10/11 spending conditions and asserting expected shape. cdk already implements P2PKConditions decoding; this is composition, not new crypto.

Caveat: this is a *commitment* primitive, not a *payment* primitive. The receiver never gets value. Useful for rate-limiting, anti-spam, "skin in the game" — not for actually charging users. Worth being explicit about the difference in any v0.2 README.
