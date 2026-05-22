//! Cashu payment-method validator for MPP.
//!
//! Wraps `cashu-mpp-core` (the wire format) with the cashu-specific bits:
//! decoding `cashuB...` tokens, checking mint/unit/amount policy, and verifying
//! proof state via NUT-07 `post_check_state` against the originating mint.
//!
//! The entry point is [`CashuMpp::authorize`]: hand it `&http::HeaderMap` plus
//! the path+query of the incoming request, and it returns an [`Outcome`] you
//! map to whichever HTTP framework you're using. There's no axum, actix, or
//! tower coupling — just types from the `http` crate.
//!
//! Example wiring inside an axum handler:
//!
//! ```ignore
//! use cashu_mpp_cashu::{CashuMpp, Outcome};
//!
//! async fn handler(
//!     State(mpp): State<CashuMpp>,
//!     OriginalUri(uri): OriginalUri,
//!     headers: HeaderMap,
//! ) -> Response {
//!     let url = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
//!     match mpp.authorize(&headers, url).await {
//!         Outcome::Authorized(payment) => {
//!             // do work, then mint a Payment-Receipt:
//!             let receipt = payment.receipt_header_value().unwrap();
//!             // ... build response with header
//!         }
//!         Outcome::NeedsPayment(c) => {
//!             // 402 + WWW-Authenticate
//!         }
//!         Outcome::Rejected(p) => {
//!             // problem+json with status p.status
//!         }
//!     }
//! }
//! ```

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use cashu_mpp_core::{Challenge, Credential, HmacKey, Receipt, Settlement};
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::token::Token;
use cdk::nuts::nut07::{CheckStateRequest, State as ProofStateValue};
use cdk::nuts::{CurrencyUnit, PaymentRequest, Proofs};
use cdk::wallet::{HttpClient, MintConnector};
use chrono::Utc;
use http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use thiserror::Error;

const DEFAULT_METHOD: &str = "cashu";
const DEFAULT_INTENT: &str = "charge";
const DEFAULT_TTL_SECS: i64 = 300;
const PROBLEM_BASE: &str = "https://paymentauth.org/problems";

#[derive(Debug, Error)]
pub enum BuildError {
    #[error("price must be > 0")]
    ZeroPrice,
    #[error("at least one allowed mint must be configured")]
    NoMints,
    #[error("invalid mint URL: {0}")]
    BadMintUrl(String),
}

/// Builder for [`CashuMpp`].
#[derive(Default)]
pub struct CashuMppBuilder {
    realm: Option<String>,
    method: Option<String>,
    intent: Option<String>,
    price_sats: Option<u64>,
    currency: Option<CurrencyUnit>,
    description: Option<String>,
    mint_urls: Vec<String>,
    challenge_ttl: Option<Duration>,
    hmac_key: Option<HmacKey>,
}

impl CashuMppBuilder {
    pub fn realm(mut self, realm: impl Into<String>) -> Self {
        self.realm = Some(realm.into());
        self
    }
    pub fn method(mut self, method: impl Into<String>) -> Self {
        self.method = Some(method.into());
        self
    }
    pub fn intent(mut self, intent: impl Into<String>) -> Self {
        self.intent = Some(intent.into());
        self
    }
    /// Set the price in the currency's base unit (sat, msat, ...).
    pub fn price(mut self, amount: u64) -> Self {
        self.price_sats = Some(amount);
        self
    }
    pub fn currency(mut self, unit: CurrencyUnit) -> Self {
        self.currency = Some(unit);
        self
    }
    pub fn description(mut self, d: impl Into<String>) -> Self {
        self.description = Some(d.into());
        self
    }
    pub fn allowed_mint(mut self, url: impl Into<String>) -> Self {
        self.mint_urls.push(url.into());
        self
    }
    pub fn challenge_ttl(mut self, d: Duration) -> Self {
        self.challenge_ttl = Some(d);
        self
    }
    /// Override the HMAC key. If unset, a fresh random 32-byte key is generated.
    pub fn hmac_key(mut self, key: HmacKey) -> Self {
        self.hmac_key = Some(key);
        self
    }

    pub fn build(self) -> Result<CashuMpp, BuildError> {
        let price = self.price_sats.ok_or(BuildError::ZeroPrice)?;
        if price == 0 {
            return Err(BuildError::ZeroPrice);
        }
        if self.mint_urls.is_empty() {
            return Err(BuildError::NoMints);
        }
        let mut mints: Vec<MintUrl> = Vec::with_capacity(self.mint_urls.len());
        let mut clients: HashMap<MintUrl, Arc<HttpClient>> = HashMap::new();
        for raw in &self.mint_urls {
            let mu = MintUrl::from_str(raw).map_err(|_| BuildError::BadMintUrl(raw.clone()))?;
            let client = HttpClient::new(mu.clone(), None);
            clients.insert(mu.clone(), Arc::new(client));
            mints.push(mu);
        }
        Ok(CashuMpp {
            realm: self.realm.unwrap_or_else(|| "cashu-mpp".to_string()),
            method: self.method.unwrap_or_else(|| DEFAULT_METHOD.to_string()),
            intent: self.intent.unwrap_or_else(|| DEFAULT_INTENT.to_string()),
            price,
            currency: self.currency.unwrap_or(CurrencyUnit::Sat),
            description: self.description,
            mints,
            clients,
            ttl: self
                .challenge_ttl
                .unwrap_or_else(|| Duration::from_secs(DEFAULT_TTL_SECS as u64)),
            hmac_key: self.hmac_key.unwrap_or_else(cashu_mpp_core::fresh_hmac_key),
        })
    }
}

/// Validator for the cashu MPP method.
///
/// Holds the realm, allowlist, HMAC key, and a per-mint cdk HTTP client. Cheap
/// to clone (everything is Arc'd internally). Build with [`CashuMpp::builder`].
#[derive(Clone)]
pub struct CashuMpp {
    realm: String,
    method: String,
    intent: String,
    price: u64,
    currency: CurrencyUnit,
    description: Option<String>,
    mints: Vec<MintUrl>,
    clients: HashMap<MintUrl, Arc<HttpClient>>,
    ttl: Duration,
    hmac_key: HmacKey,
}

impl CashuMpp {
    pub fn builder() -> CashuMppBuilder {
        CashuMppBuilder::default()
    }

    pub fn realm(&self) -> &str {
        &self.realm
    }
    pub fn price(&self) -> u64 {
        self.price
    }
    pub fn currency(&self) -> &CurrencyUnit {
        &self.currency
    }
    pub fn allowed_mints(&self) -> &[MintUrl] {
        &self.mints
    }

    /// Decide what to do with a request: serve, ask for payment, or reject.
    ///
    /// `url_path_and_query` should be the path+query of the incoming request
    /// (e.g. `/random?bits=128`). It gets bound into the challenge via the
    /// `opaque` field so a credential issued for one URL can't be replayed
    /// against another.
    pub async fn authorize(&self, headers: &HeaderMap, url_path_and_query: &str) -> Outcome {
        match headers.get(http::header::AUTHORIZATION) {
            None => Outcome::NeedsPayment(self.build_challenge(url_path_and_query)),
            Some(value) => {
                let s = match value.to_str() {
                    Ok(s) => s,
                    Err(_) => {
                        return Outcome::Rejected(problem(
                            StatusCode::BAD_REQUEST,
                            "malformed-credential",
                            "Malformed Credential",
                            "Authorization header is not valid UTF-8",
                        ));
                    }
                };
                match self.validate(s, url_path_and_query).await {
                    Ok(payment) => Outcome::Authorized(payment),
                    Err(reason) => Outcome::Rejected(problem(
                        StatusCode::PAYMENT_REQUIRED,
                        "verification-failed",
                        "Payment Verification Failed",
                        &reason,
                    )),
                }
            }
        }
    }

    /// Build a 402 challenge response for `url_path_and_query`. Usually called
    /// indirectly via [`authorize`], but exposed for callers that want to issue
    /// a challenge proactively (e.g. an out-of-band quote endpoint).
    pub fn build_challenge(&self, url_path_and_query: &str) -> ChallengeResponse {
        let mints_strs: Vec<String> = self.mints.iter().map(|m| m.to_string()).collect();

        let pr_builder = PaymentRequest::builder()
            .amount(self.price)
            .unit(self.currency.clone());
        let pr_builder = self
            .mints
            .iter()
            .fold(pr_builder, |b, m| b.add_mint(m.clone()))
            .single_use(true);
        let pr_builder = match &self.description {
            Some(d) => pr_builder.description(d.clone()),
            None => pr_builder,
        };
        let nut18 = pr_builder.build().to_string();

        let req = CashuRequestBlob {
            amount: self.price.to_string(),
            currency: currency_code(&self.currency).to_string(),
            mints: mints_strs.clone(),
            nut18,
        };
        let request_b64 = match cashu_mpp_core::encode_jcs_b64(&req) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("encode request: {e}");
                return ChallengeResponse::server_error("failed to build payment request");
            }
        };

        let opaque = CashuOpaqueBlob {
            url: url_path_and_query.to_string(),
        };
        let opaque_b64 = match cashu_mpp_core::encode_jcs_b64(&opaque) {
            Ok(v) => v,
            Err(e) => {
                tracing::error!("encode opaque: {e}");
                return ChallengeResponse::server_error("failed to build opaque");
            }
        };

        let expires = (Utc::now()
            + chrono::Duration::from_std(self.ttl).unwrap_or(chrono::Duration::seconds(300)))
        .to_rfc3339();

        let challenge = Challenge {
            realm: self.realm.clone(),
            method: self.method.clone(),
            intent: self.intent.clone(),
            request: request_b64,
            expires: Some(expires),
            digest: None,
            opaque: Some(opaque_b64),
        };
        let id = challenge.bound_id(&self.hmac_key);
        let www_auth = challenge.auth_header_value(&self.hmac_key);

        let body = json!({
            "type": format!("{PROBLEM_BASE}/payment-required"),
            "title": "Payment Required",
            "status": 402,
            "detail": format!(
                "This resource costs {} {} (mint: {}).",
                self.price,
                currency_code(&self.currency),
                self.mints.first().map(|m| m.to_string()).unwrap_or_default(),
            ),
            "challengeId": id,
        });

        ChallengeResponse {
            status: StatusCode::PAYMENT_REQUIRED,
            www_authenticate: www_auth,
            body,
            challenge_id: id,
        }
    }

    async fn validate(
        &self,
        auth_header: &str,
        url_for_binding: &str,
    ) -> Result<ValidatedPayment, String> {
        let cred = Credential::from_auth_header_value(auth_header)
            .map_err(|e| format!("parse credential: {e}"))?;

        if cred.challenge.method != self.method {
            return Err(format!(
                "method must be \"{}\", got \"{}\"",
                self.method, cred.challenge.method
            ));
        }
        if cred.challenge.realm != self.realm {
            return Err(format!(
                "realm must be \"{}\", got \"{}\"",
                self.realm, cred.challenge.realm
            ));
        }
        if cred.challenge.intent != self.intent {
            return Err(format!(
                "intent must be \"{}\", got \"{}\"",
                self.intent, cred.challenge.intent
            ));
        }

        cred.verify_binding(&self.hmac_key)
            .map_err(|e| format!("challenge binding: {e}"))?;
        cred.verify_not_expired(Utc::now())
            .map_err(|e| format!("challenge expiry: {e}"))?;

        let opaque_b64 = cred
            .challenge
            .opaque
            .as_deref()
            .ok_or_else(|| "challenge missing opaque field".to_string())?;
        let opaque: CashuOpaqueBlob =
            cashu_mpp_core::decode_jcs_b64(opaque_b64).map_err(|e| format!("decode opaque: {e}"))?;
        if opaque.url != url_for_binding {
            return Err(format!(
                "opaque url \"{}\" does not match request url \"{url_for_binding}\"",
                opaque.url
            ));
        }

        let req: CashuRequestBlob = cashu_mpp_core::decode_jcs_b64(&cred.challenge.request)
            .map_err(|e| format!("decode request: {e}"))?;
        let expected_currency = currency_code(&self.currency);
        if req.currency != expected_currency {
            return Err(format!(
                "currency must be {expected_currency}, got {}",
                req.currency
            ));
        }
        let priced: u64 = req
            .amount
            .parse()
            .map_err(|e| format!("parse amount: {e}"))?;
        if priced != self.price {
            return Err(format!(
                "amount {priced} does not match server price {}",
                self.price
            ));
        }

        let payload: CashuPayload = serde_json::from_value(cred.payload.clone())
            .map_err(|e| format!("decode payload: {e}"))?;
        let token_str = payload.token.trim();
        let token = Token::from_str(token_str).map_err(|e| format!("decode token: {e}"))?;

        match token.unit() {
            Some(u) if &u == self.currency() => {}
            Some(other) => return Err(format!("unit must be {expected_currency}, got {other:?}")),
            None => return Err("token missing unit".to_string()),
        }

        let token_mint = token.mint_url().map_err(|e| format!("token mint: {e}"))?;
        if !self.mints.iter().any(|m| m == &token_mint) {
            return Err(format!(
                "mint not allowed: token mint {token_mint} not in allowlist"
            ));
        }

        let client = self
            .clients
            .get(&token_mint)
            .ok_or_else(|| format!("no client for mint {token_mint}"))?;

        let keysets = client
            .get_mint_keysets()
            .await
            .map_err(|e| format!("fetch mint keysets: {e}"))?
            .keysets;

        let proofs: Proofs = token
            .proofs(&keysets)
            .map_err(|e| format!("expand proofs: {e}"))?;

        let total: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
        if total < self.price {
            return Err(format!(
                "amount {total} is below price {}",
                self.price
            ));
        }

        let ys = proofs
            .iter()
            .map(|p| p.y().map_err(|e| format!("hash_to_curve: {e}")))
            .collect::<Result<Vec<_>, _>>()?;

        let check = client
            .post_check_state(CheckStateRequest { ys })
            .await
            .map_err(|e| format!("checkstate: {e}"))?;

        for (i, st) in check.states.iter().enumerate() {
            if st.state != ProofStateValue::Unspent {
                return Err(format!("proof[{i}] state is {:?}, expected Unspent", st.state));
            }
        }

        Ok(ValidatedPayment {
            amount: total,
            mint: token_mint,
            proofs,
            challenge_id: cred.id,
            token: token_str.to_string(),
            currency: self.currency.clone(),
            method: self.method.clone(),
        })
    }
}

/// What the consumer should do with this request.
pub enum Outcome {
    /// Token was good. Serve the response and emit a `Payment-Receipt` header from `ValidatedPayment::receipt_header_value`.
    Authorized(ValidatedPayment),
    /// No Authorization header present. Return 402 with these headers + body.
    NeedsPayment(ChallengeResponse),
    /// Authorization header was present but invalid. Return the problem response.
    Rejected(ProblemResponse),
}

/// Components of a 402 challenge response. Map these into your framework's response type.
pub struct ChallengeResponse {
    pub status: StatusCode,
    pub www_authenticate: String,
    pub body: Value,
    pub challenge_id: String,
}

impl ChallengeResponse {
    fn server_error(detail: &str) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            www_authenticate: String::new(),
            body: problem_body("server-error", "Server Error", detail, 500),
            challenge_id: String::new(),
        }
    }
}

/// Components of a non-success response (problem+json).
pub struct ProblemResponse {
    pub status: StatusCode,
    pub body: Value,
}

fn problem(status: StatusCode, slug: &str, title: &str, detail: &str) -> ProblemResponse {
    tracing::warn!(status = %status.as_u16(), slug, detail, "MPP rejection");
    ProblemResponse {
        status,
        body: problem_body(slug, title, detail, status.as_u16()),
    }
}

fn problem_body(slug: &str, title: &str, detail: &str, status: u16) -> Value {
    json!({
        "type": format!("{PROBLEM_BASE}/{slug}"),
        "title": title,
        "status": status,
        "detail": detail,
    })
}

/// A successfully validated cashu payment.
pub struct ValidatedPayment {
    pub amount: u64,
    pub mint: MintUrl,
    pub proofs: Proofs,
    pub challenge_id: String,
    pub token: String,
    pub currency: CurrencyUnit,
    pub method: String,
}

impl ValidatedPayment {
    /// Number of proofs covered by the validation.
    pub fn proof_count(&self) -> usize {
        self.proofs.len()
    }

    /// Build the value for the `Payment-Receipt` header. Reference is the
    /// hex-encoded SHA-256 of the token string — a non-secret correlation
    /// handle that lets a receipt-holder prove "I paid with this token."
    pub fn receipt_header_value(&self) -> Result<String, cashu_mpp_core::MppError> {
        let reference = hex::encode(sha2::Sha256::digest(self.token.as_bytes()));
        let receipt = Receipt {
            challenge_id: self.challenge_id.clone(),
            method: self.method.clone(),
            reference,
            settlement: Settlement {
                amount: self.amount.to_string(),
                currency: currency_code(&self.currency).to_string(),
            },
            status: "success".to_string(),
            timestamp: Utc::now().to_rfc3339(),
        };
        receipt.to_header_value()
    }
}

/// JCS-encoded request body for `method=cashu`.
#[derive(Serialize, Deserialize)]
struct CashuRequestBlob {
    amount: String,
    currency: String,
    mints: Vec<String>,
    nut18: String,
}

/// JCS-encoded opaque body — binds the challenge to the originating URL.
#[derive(Serialize, Deserialize)]
struct CashuOpaqueBlob {
    url: String,
}

/// Method-specific credential payload for `method=cashu`.
#[derive(Serialize, Deserialize)]
struct CashuPayload {
    token: String,
}

fn currency_code(unit: &CurrencyUnit) -> &'static str {
    match unit {
        CurrencyUnit::Sat => "sat",
        CurrencyUnit::Msat => "msat",
        CurrencyUnit::Usd => "usd",
        _ => "sat",
    }
}
