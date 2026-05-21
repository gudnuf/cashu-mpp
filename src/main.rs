//! cashu-mpp v0.1 — NUT-24 HTTP 402 + cashu demo server.
//!
//! Single route: GET /random?bits=N. No X-Cashu header → 402 with a NUT-18
//! payment request. With X-Cashu cashuB token → validate against the allowed
//! mint via NUT-07 checkstate and return random bytes.
//!
//! Validation only. No /melt redemption.

use std::str::FromStr;
use std::sync::Arc;

use anyhow::Result;
use axum::extract::{Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use cdk::mint_url::MintUrl;
use cdk::nuts::nut00::token::Token;
use cdk::nuts::nut07::{CheckStateRequest, State as ProofStateValue};
use cdk::nuts::{CurrencyUnit, PaymentRequest};
use cdk::wallet::{HttpClient, MintConnector};
use rand::Rng;
use serde::Deserialize;
use serde_json::json;

const PRICE_SATS: u64 = 10;
const ALLOWED_MINT: &str = "https://testnut.cashu.space";
const LISTEN_ADDR: &str = "0.0.0.0:3000";
const DEFAULT_BITS: u32 = 128;
const MAX_BITS: u32 = 4096;

#[derive(Clone)]
struct AppState {
    mint_url: MintUrl,
    client: Arc<HttpClient>,
}

#[derive(Deserialize)]
struct RandomQuery {
    #[serde(default)]
    bits: Option<u32>,
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

    let state = AppState {
        mint_url,
        client: Arc::new(client),
    };

    let app = Router::new()
        .route("/random", get(handle_random))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR).await?;
    tracing::info!(
        "cashu-mpp v0.1 listening on http://{LISTEN_ADDR}  mint={ALLOWED_MINT}  price={PRICE_SATS} sat"
    );
    axum::serve(listener, app).await?;
    Ok(())
}

async fn handle_random(
    State(state): State<AppState>,
    Query(q): Query<RandomQuery>,
    headers: HeaderMap,
) -> Response {
    let bits = q.bits.unwrap_or(DEFAULT_BITS);
    if bits == 0 || bits > MAX_BITS {
        return bad_request(format!("bits must be 1..={MAX_BITS}"));
    }

    match headers.get("x-cashu") {
        None => payment_required(&state.mint_url),
        Some(value) => match value.to_str() {
            Ok(token_str) => match validate_and_serve(&state, token_str.trim(), bits).await {
                Ok(resp) => resp,
                Err(reason) => bad_request(reason),
            },
            Err(_) => bad_request("X-Cashu header is not valid UTF-8".to_string()),
        },
    }
}

fn payment_required(mint_url: &MintUrl) -> Response {
    let payment_request = PaymentRequest::builder()
        .amount(PRICE_SATS)
        .unit(CurrencyUnit::Sat)
        .add_mint(mint_url.clone())
        .single_use(true)
        .description("cashu-mpp: random bytes via NUT-24".to_string())
        .build();

    let creq = payment_request.to_string();

    let mut hdrs = HeaderMap::new();
    match HeaderValue::from_str(&creq) {
        Ok(v) => {
            hdrs.insert("x-cashu", v);
        }
        Err(e) => {
            tracing::error!("failed to build x-cashu header value: {e}");
            return internal("failed to encode payment request");
        }
    }
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    let body = Json(json!({
        "error": "payment required",
        "price_sats": PRICE_SATS,
        "unit": "sat",
        "mint": ALLOWED_MINT,
        "payment_request": creq,
    }));

    (StatusCode::PAYMENT_REQUIRED, hdrs, body).into_response()
}

async fn validate_and_serve(
    state: &AppState,
    token_str: &str,
    bits: u32,
) -> Result<Response, String> {
    let token = Token::from_str(token_str).map_err(|e| format!("decode token: {e}"))?;

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
    rand::rng().fill_bytes(&mut buf);

    let body = Json(json!({
        "bits": bits,
        "random_hex": hex_encode(&buf),
        "amount_paid": total,
        "mint": ALLOWED_MINT,
        "unit": "sat",
        "proofs_checked": proofs.len(),
    }));

    Ok((StatusCode::OK, body).into_response())
}

fn bad_request(reason: String) -> Response {
    tracing::warn!(reason = %reason, "rejecting request");
    (StatusCode::BAD_REQUEST, Json(json!({ "error": reason }))).into_response()
}

fn internal(msg: &str) -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(json!({ "error": msg })),
    )
        .into_response()
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}
