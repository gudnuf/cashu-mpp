//! random-server — demo consumer of `cashu-mpp-cashu`.
//!
//! Single route: `GET /random?bits=N`. Returns N bits of random hex, gated
//! behind a 10-sat cashu payment over MPP. The server is just glue: build a
//! CashuMpp at startup, call `.authorize()` in the handler, map the Outcome
//! to axum response types.

use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::extract::{OriginalUri, Query, State};
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use cashu_mpp_cashu::{CashuMpp, ChallengeResponse, Outcome, ProblemResponse, ValidatedPayment};
use serde::Deserialize;
use serde_json::{json, Value};

const ALLOWED_MINT: &str = "https://testnut.cashu.space";
const LISTEN_ADDR: &str = "0.0.0.0:3000";
const PRICE_SATS: u64 = 10;
const DEFAULT_BITS: u32 = 128;
const MAX_BITS: u32 = 4096;
const PROBLEM_BASE: &str = "https://paymentauth.org/problems";

#[derive(Clone)]
struct AppState {
    mpp: Arc<CashuMpp>,
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
                .unwrap_or_else(|_| "random_server=info,cashu_mpp_cashu=info".into()),
        )
        .init();

    let mpp = CashuMpp::builder()
        .realm("cashu-mpp")
        .price(PRICE_SATS)
        .allowed_mint(ALLOWED_MINT)
        .description("cashu-mpp: random bytes via MPP")
        .challenge_ttl(Duration::from_secs(300))
        .build()?;

    let state = AppState { mpp: Arc::new(mpp) };

    let app = Router::new()
        .route("/random", get(handle_random))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(LISTEN_ADDR).await?;
    tracing::info!("random-server listening on http://{LISTEN_ADDR}");
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
        return problem_response(
            StatusCode::BAD_REQUEST,
            "bad-request",
            "Bad Request",
            &format!("bits must be 1..={MAX_BITS}"),
        );
    }

    let url = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    match state.mpp.authorize(&headers, &url).await {
        Outcome::Authorized(payment) => serve_random(payment, bits),
        Outcome::NeedsPayment(c) => challenge_into_response(c),
        Outcome::Rejected(p) => problem_into_response(p),
    }
}

fn serve_random(payment: ValidatedPayment, bits: u32) -> Response {
    let nbytes = bits.div_ceil(8) as usize;
    let mut buf = vec![0u8; nbytes];
    {
        use rand::Rng;
        rand::rng().fill_bytes(&mut buf);
    }

    let receipt_b64 = match payment.receipt_header_value() {
        Ok(v) => v,
        Err(e) => {
            return problem_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server-error",
                "Server Error",
                &format!("build receipt: {e}"),
            );
        }
    };

    let body: Value = json!({
        "bits": bits,
        "random_hex": hex_encode(&buf),
        "amount_paid": payment.amount,
        "mint": payment.mint.to_string(),
        "unit": "sat",
        "proofs_checked": payment.proof_count(),
    });

    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        "payment-receipt",
        match HeaderValue::from_str(&receipt_b64) {
            Ok(v) => v,
            Err(e) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server-error",
                    "Server Error",
                    &format!("payment-receipt header: {e}"),
                );
            }
        },
    );
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );

    (StatusCode::OK, hdrs, Json(body)).into_response()
}

fn challenge_into_response(c: ChallengeResponse) -> Response {
    let mut hdrs = HeaderMap::new();
    if !c.www_authenticate.is_empty() {
        match HeaderValue::from_str(&c.www_authenticate) {
            Ok(v) => {
                hdrs.insert(header::WWW_AUTHENTICATE, v);
            }
            Err(e) => {
                return problem_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server-error",
                    "Server Error",
                    &format!("WWW-Authenticate header: {e}"),
                );
            }
        }
    }
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    hdrs.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));

    (c.status, hdrs, Json(c.body)).into_response()
}

fn problem_into_response(p: ProblemResponse) -> Response {
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    (p.status, hdrs, Json(p.body)).into_response()
}

fn problem_response(status: StatusCode, slug: &str, title: &str, detail: &str) -> Response {
    tracing::warn!(status = %status.as_u16(), slug, detail, "rejecting");
    let body = Json(json!({
        "type": format!("{PROBLEM_BASE}/{slug}"),
        "title": title,
        "status": status.as_u16(),
        "detail": detail,
    }));
    let mut hdrs = HeaderMap::new();
    hdrs.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/problem+json"),
    );
    (status, hdrs, body).into_response()
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
