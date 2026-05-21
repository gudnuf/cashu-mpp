//! cashu-mpp v0.2 — MPP-framed HTTP 402 + cashu demo server.
//!
//! Wire format follows <https://mpp.dev>: `WWW-Authenticate: Payment ...` on
//! the 402, `Authorization: Payment <base64url(JSON)>` on the retry,
//! `Payment-Receipt: <base64url(JSON)>` on the 200. `cashu` is a non-registered
//! payment method — the body of the WWW-Authenticate `request` parameter
//! carries the NUT-18 creqA blob alongside parsed fields so non-cashu clients
//! can introspect.
//!
//! Validation only: server runs NUT-07 checkstate against the allowed mint and
//! returns the resource. No /melt redemption.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{OriginalUri, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::token::Token;
use cdk::nuts::nut07::{CheckStateRequest, State as ProofStateValue};
use cdk::nuts::{CurrencyUnit, PaymentRequest};
use cdk::wallet::{HttpClient, MintConnector};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;

use cashu_mpp::mpp;
use cashu_mpp::mpp::{Challenge, Credential, HmacKey, Receipt, Settlement};

const PRICE_SATS: u64 = 10;
const ALLOWED_MINT: &str = "https://testnut.cashu.space";
const LISTEN_ADDR: &str = "0.0.0.0:3000";
const DEFAULT_BITS: u32 = 128;
const MAX_BITS: u32 = 4096;
const REALM: &str = "cashu-mpp";
const METHOD: &str = "cashu";
const INTENT: &str = "charge";
const CHALLENGE_TTL_SECS: i64 = 300;
const PROBLEM_BASE: &str = "https://paymentauth.org/problems";

#[derive(Clone)]
struct AppState {
    mint_url: MintUrl,
    client: Arc<HttpClient>,
    hmac_key: HmacKey,
}

#[derive(Deserialize)]
struct RandomQuery {
    #[serde(default)]
    bits: Option<u32>,
}

/// JCS-encoded request body for `method=cashu`.
#[derive(Serialize, Deserialize)]
struct CashuRequest {
    amount: String,
    currency: String,
    mints: Vec<String>,
    /// Full NUT-18 creqA blob, so cashu-aware clients can decode natively.
    nut18: String,
}

/// JCS-encoded opaque body — binds the challenge to the originating URL.
#[derive(Serialize, Deserialize)]
struct CashuOpaque {
    url: String,
}

/// Method-specific credential payload for `method=cashu`.
#[derive(Serialize, Deserialize)]
struct CashuPayload {
    token: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "cashu_mpp=info,tower_http=info".into()),
        )
        .init();

    let mint_url = MintUrl::from_str(ALLOWED_MINT)?;
    let client: HttpClient = HttpClient::new(mint_url.clone(), None);
    let hmac_key = mpp::fresh_hmac_key();

    let state = AppState {
        mint_url,
        client: Arc::new(client),
        hmac_key,
    };

    let app = Router::new()
        .route("/random", get(handle_random))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR).await?;
    tracing::info!(
        "cashu-mpp v0.2 listening on http://{LISTEN_ADDR}  mint={ALLOWED_MINT}  price={PRICE_SATS} sat  realm={REALM}  method={METHOD}"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_random(
    State(state): State<AppState>,
    OriginalUri(uri): OriginalUri,
    Query(q): Query<RandomQuery>,
    headers: HeaderMap,
) -> Response {
    let bits = q.bits.unwrap_or(DEFAULT_BITS);
    if bits == 0 || bits > MAX_BITS {
        return problem(
            StatusCode::BAD_REQUEST,
            "bad-request",
            "Bad Request",
            format!("bits must be 1..={MAX_BITS}"),
        );
    }

    let url_for_binding = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/").to_string();

    match headers.get(header::AUTHORIZATION) {
        None => payment_required(&state, &url_for_binding).await,
        Some(value) => match value.to_str() {
            Ok(s) => match validate_and_serve(&state, s, &url_for_binding, bits).await {
                Ok(resp) => resp,
                Err(reason) => problem(
                    StatusCode::PAYMENT_REQUIRED,
                    "verification-failed",
                    "Payment Verification Failed",
                    reason,
                ),
            },
            Err(_) => problem(
                StatusCode::BAD_REQUEST,
                "malformed-credential",
                "Malformed Credential",
                "Authorization header is not valid UTF-8".to_string(),
            ),
        },
    }
}

async fn payment_required(state: &AppState, url_for_binding: &str) -> Response {
    let payment_request = PaymentRequest::builder()
        .amount(PRICE_SATS)
        .unit(CurrencyUnit::Sat)
        .add_mint(state.mint_url.clone())
        .single_use(true)
        .description("cashu-mpp: random bytes via MPP".to_string())
        .build();
    let nut18 = payment_request.to_string();

    let req = CashuRequest {
        amount: PRICE_SATS.to_string(),
        currency: "sat".to_string(),
        mints: vec![ALLOWED_MINT.to_string()],
        nut18,
    };
    let request_b64 = match mpp::encode_jcs_b64(&req) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("encode request: {e}");
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server-error",
                "Server Error",
                "failed to build payment request".to_string(),
            );
        }
    };

    let opaque = CashuOpaque {
        url: url_for_binding.to_string(),
    };
    let opaque_b64 = match mpp::encode_jcs_b64(&opaque) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("encode opaque: {e}");
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server-error",
                "Server Error",
                "failed to build opaque".to_string(),
            );
        }
    };

    let expires = (Utc::now() + chrono::Duration::seconds(CHALLENGE_TTL_SECS)).to_rfc3339();

    let challenge = Challenge {
        realm: REALM.to_string(),
        method: METHOD.to_string(),
        intent: INTENT.to_string(),
        request: request_b64,
        expires: Some(expires),
        digest: None,
        opaque: Some(opaque_b64),
    };
    let id = challenge.bound_id(&state.hmac_key);
    let www_auth = challenge.auth_header_value(&state.hmac_key);

    let mut hdrs = HeaderMap::new();
    match HeaderValue::from_str(&www_auth) {
        Ok(v) => {
            hdrs.insert(header::WWW_AUTHENTICATE, v);
        }
        Err(e) => {
            tracing::error!("build WWW-Authenticate header: {e}");
            return problem(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server-error",
                "Server Error",
                "header construction".to_string(),
            );
        }
    }
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    hdrs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    let body = Json(json!({
        "type": format!("{PROBLEM_BASE}/payment-required"),
        "title": "Payment Required",
        "status": 402,
        "detail": format!("This resource costs {PRICE_SATS} sat (mint: {ALLOWED_MINT})."),
        "challengeId": id,
    }));

    (StatusCode::PAYMENT_REQUIRED, hdrs, body).into_response()
}

async fn validate_and_serve(
    state: &AppState,
    auth_header: &str,
    url_for_binding: &str,
    bits: u32,
) -> Result<Response, String> {
    let cred =
        Credential::from_auth_header_value(auth_header).map_err(|e| format!("parse credential: {e}"))?;

    if cred.challenge.method != METHOD {
        return Err(format!(
            "method must be \"{METHOD}\", got \"{}\"",
            cred.challenge.method
        ));
    }
    if cred.challenge.realm != REALM {
        return Err(format!(
            "realm must be \"{REALM}\", got \"{}\"",
            cred.challenge.realm
        ));
    }
    if cred.challenge.intent != INTENT {
        return Err(format!(
            "intent must be \"{INTENT}\", got \"{}\"",
            cred.challenge.intent
        ));
    }

    cred.verify_binding(&state.hmac_key)
        .map_err(|e| format!("challenge binding: {e}"))?;
    cred.verify_not_expired(Utc::now())
        .map_err(|e| format!("challenge expiry: {e}"))?;

    // Verify the request was retried against the same URL the 402 came from.
    let opaque_b64 = cred
        .challenge
        .opaque
        .as_deref()
        .ok_or_else(|| "challenge missing opaque field".to_string())?;
    let opaque: CashuOpaque = mpp::decode_jcs_b64(opaque_b64)
        .map_err(|e| format!("decode opaque: {e}"))?;
    if opaque.url != url_for_binding {
        return Err(format!(
            "opaque url \"{}\" does not match request url \"{url_for_binding}\"",
            opaque.url
        ));
    }

    // Sanity-check the cashu request blob still matches our policy.
    let req: CashuRequest = mpp::decode_jcs_b64(&cred.challenge.request)
        .map_err(|e| format!("decode request: {e}"))?;
    if req.currency != "sat" {
        return Err(format!("currency must be sat, got {}", req.currency));
    }
    let priced: u64 = req
        .amount
        .parse()
        .map_err(|e| format!("parse amount: {e}"))?;
    if priced != PRICE_SATS {
        return Err(format!(
            "amount {priced} sat does not match server price {PRICE_SATS} sat"
        ));
    }

    let payload: CashuPayload =
        serde_json::from_value(cred.payload.clone()).map_err(|e| format!("decode payload: {e}"))?;
    let token = Token::from_str(payload.token.trim()).map_err(|e| format!("decode token: {e}"))?;

    match token.unit() {
        Some(CurrencyUnit::Sat) => {}
        Some(other) => return Err(format!("unit must be sat, got {other:?}")),
        None => return Err("token missing unit".to_string()),
    }

    let token_mint = token.mint_url().map_err(|e| format!("token mint: {e}"))?;
    if token_mint != state.mint_url {
        return Err(format!(
            "mint not allowed: token mint {token_mint} != allowed {}",
            state.mint_url
        ));
    }

    let keysets = state
        .client
        .get_mint_keysets()
        .await
        .map_err(|e| format!("fetch mint keysets: {e}"))?
        .keysets;

    let proofs = token
        .proofs(&keysets)
        .map_err(|e| format!("expand proofs: {e}"))?;

    let total: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
    if total < PRICE_SATS {
        return Err(format!("amount {total} sat is below price {PRICE_SATS} sat"));
    }

    let ys = proofs
        .iter()
        .map(|p| p.y().map_err(|e| format!("hash_to_curve: {e}")))
        .collect::<Result<Vec<_>, _>>()?;

    let check = state
        .client
        .post_check_state(CheckStateRequest { ys })
        .await
        .map_err(|e| format!("checkstate: {e}"))?;

    for (i, st) in check.states.iter().enumerate() {
        if st.state != ProofStateValue::Unspent {
            return Err(format!("proof[{i}] state is {:?}, expected Unspent", st.state));
        }
    }

    let nbytes = bits.div_ceil(8) as usize;
    let mut buf = vec![0u8; nbytes];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut buf);
    }

    let reference = hex::encode(sha2::Sha256::digest(payload.token.as_bytes()));
    let receipt = Receipt {
        challenge_id: cred.id.clone(),
        method: METHOD.to_string(),
        reference,
        settlement: Settlement {
            amount: total.to_string(),
            currency: "sat".to_string(),
        },
        status: "success".to_string(),
        timestamp: Utc::now().to_rfc3339(),
    };
    let receipt_b64 = receipt
        .to_header_value()
        .map_err(|e| format!("encode receipt: {e}"))?;

    let body: Value = json!({
        "bits": bits,
        "random_hex": hex::encode(&buf),
        "amount_paid": total,
        "mint": ALLOWED_MINT,
        "unit": "sat",
        "proofs_checked": proofs.len(),
    });

    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        "payment-receipt",
        HeaderValue::from_str(&receipt_b64).map_err(|e| format!("payment-receipt header: {e}"))?,
    );
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    Ok((StatusCode::OK, hdrs, Json(body)).into_response())
}

fn problem(status: StatusCode, slug: &str, title: &str, detail: String) -> Response {
    tracing::warn!(status=%status.as_u16(), slug, detail = %detail, "problem response");
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    let body = Json(json!({
        "type": format!("{PROBLEM_BASE}/{slug}"),
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
    }));
    (status, hdrs, body).into_response()
}

