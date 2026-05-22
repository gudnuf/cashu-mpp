//! Smoke test for the cashu-mpp v0.2 server (MPP wire format).
//!
//! Mints 10 sat from `testnut.cashu.space` via the cdk crate, then drives the
//! full MPP handshake:
//!     1. GET /random → expect 402 + WWW-Authenticate: Payment
//!     2. Parse the challenge, build a Credential carrying the cashuB token
//!     3. GET /random with Authorization: Payment <...> → expect 200 + Payment-Receipt
//!
//! Run order:
//!     terminal A:  cargo run
//!     terminal B:  cargo run --example smoke

use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cashu_mpp_core::{self as mpp, Credential};
use cdk::amount::{Amount, SplitTarget};
use cdk::mint_url::MintUrl;
use cdk::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
use cdk::wallet::{SendOptions, WalletBuilder};
use rand::Rng;
use serde::Deserialize;
use serde_json::Value;

const MINT_URL: &str = "https://testnut.cashu.space";
const SERVER_URL: &str = "http://127.0.0.1:3000/random?bits=128";
const AMOUNT_SATS: u64 = 10;
const MINT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MINT_POLL_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Deserialize)]
struct CashuRequestBlob {
    amount: String,
    currency: String,
    mints: Vec<String>,
    nut18: String,
}

#[derive(Deserialize, Debug)]
struct ReceiptShape {
    #[serde(rename = "challengeId")]
    challenge_id: String,
    method: String,
    reference: String,
    settlement: SettlementShape,
    status: String,
    timestamp: String,
}

#[derive(Deserialize, Debug)]
struct SettlementShape {
    amount: String,
    currency: String,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => {
            println!("\n[smoke] PASS");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("\n[smoke] FAIL: {e:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    println!("[smoke] step 1: build in-memory wallet against {MINT_URL}");
    let db = cdk_sqlite::wallet::memory::empty()
        .await
        .context("init in-memory wallet db")?;
    let mut seed = [0u8; 64];
    rand::rng().fill_bytes(&mut seed[..]);

    let wallet = WalletBuilder::new()
        .mint_url(MintUrl::from_str(MINT_URL)?)
        .unit(CurrencyUnit::Sat)
        .localstore(Arc::new(db))
        .seed(seed)
        .build()?;

    println!("[smoke] step 2: mint {AMOUNT_SATS} sat against testnut (auto-settle)");
    let quote = wallet
        .mint_quote(
            PaymentMethod::BOLT11,
            Some(Amount::from(AMOUNT_SATS)),
            None,
            None,
        )
        .await
        .context("mint_quote")?;
    let quote_id = quote.id.clone();
    let deadline = std::time::Instant::now() + MINT_POLL_TIMEOUT;
    loop {
        let q = wallet
            .check_mint_quote_status(&quote_id)
            .await
            .context("check_mint_quote_status")?;
        if q.state == MintQuoteState::Paid {
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(anyhow!(
                "timed out waiting for mint quote (state={:?})",
                q.state
            ));
        }
        tokio::time::sleep(MINT_POLL_INTERVAL).await;
    }
    let proofs = wallet
        .mint(&quote_id, SplitTarget::default(), None)
        .await
        .context("mint")?;
    let minted: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
    println!("[smoke]   minted {minted} sat across {} proof(s)", proofs.len());

    let prepared = wallet
        .prepare_send(Amount::from(AMOUNT_SATS), SendOptions::default())
        .await
        .context("prepare_send")?;
    let token = prepared.confirm(None).await.context("confirm send")?;
    let token_str = token.to_string();
    let preview: String = token_str.chars().take(40).collect();
    println!("[smoke]   token = {preview}...  ({} chars)", token_str.len());

    println!("[smoke] step 3: GET {SERVER_URL} (no auth, expect 402)");
    let client = reqwest::Client::new();
    let r1 = client.get(SERVER_URL).send().await.context("GET (no auth)")?;
    if r1.status().as_u16() != 402 {
        return Err(anyhow!("expected 402, got {}", r1.status()));
    }
    let www_auth = r1
        .headers()
        .get("www-authenticate")
        .ok_or_else(|| anyhow!("response missing WWW-Authenticate header"))?
        .to_str()?
        .to_string();
    let body: Value = r1.json().await.context("parse problem+json")?;
    let problem_type = body
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !problem_type.ends_with("/payment-required") {
        return Err(anyhow!("unexpected problem type: {problem_type}"));
    }
    println!("[smoke]   402 ok; problem type = {problem_type}");

    println!("[smoke] step 4: parse WWW-Authenticate + Cashu request blob");
    let (challenge_id, challenge) = cashu_mpp_core::Challenge::parse_www_authenticate(&www_auth)
        .context("parse WWW-Authenticate")?;
    if challenge.method != "cashu" {
        return Err(anyhow!("expected method=cashu, got {}", challenge.method));
    }
    let req: CashuRequestBlob = mpp::decode_jcs_b64(&challenge.request)
        .context("decode JCS request blob")?;
    if req.currency != "sat" {
        return Err(anyhow!("expected currency=sat, got {}", req.currency));
    }
    if !req.mints.iter().any(|m| m == MINT_URL) {
        return Err(anyhow!(
            "{MINT_URL} not in challenge mint allowlist {:?}",
            req.mints
        ));
    }
    println!(
        "[smoke]   challenge id={} amount={} mints={:?}",
        &challenge_id[..16.min(challenge_id.len())],
        req.amount,
        req.mints
    );
    println!("[smoke]   server nut18 = {}", &req.nut18[..24.min(req.nut18.len())]);

    println!("[smoke] step 5: build credential and retry");
    let cred = Credential {
        challenge,
        id: challenge_id.clone(),
        source: "anonymous".to_string(),
        payload: serde_json::json!({ "token": token_str }),
    };
    let auth_header = cred.to_auth_header_value().context("encode credential")?;

    let r2 = client
        .get(SERVER_URL)
        .header("Authorization", &auth_header)
        .send()
        .await
        .context("GET (with auth)")?;
    if r2.status().as_u16() != 200 {
        let status = r2.status();
        let text = r2.text().await.unwrap_or_default();
        return Err(anyhow!("expected 200, got {status}; body={text}"));
    }
    let receipt_b64 = r2
        .headers()
        .get("payment-receipt")
        .ok_or_else(|| anyhow!("response missing Payment-Receipt header"))?
        .to_str()?
        .to_string();
    let body: Value = r2.json().await.context("parse 200 body")?;
    let random_hex = body
        .get("random_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("body missing random_hex: {body}"))?;
    if random_hex.len() != 32 {
        return Err(anyhow!(
            "expected 32 hex chars for 128 bits, got {}",
            random_hex.len()
        ));
    }
    let receipt_json = URL_SAFE_NO_PAD
        .decode(receipt_b64.as_bytes())
        .context("base64url decode receipt")?;
    let receipt: ReceiptShape =
        serde_json::from_slice(&receipt_json).context("parse receipt JSON")?;
    if receipt.method != "cashu" {
        return Err(anyhow!("receipt method = {}, expected cashu", receipt.method));
    }
    if receipt.status != "success" {
        return Err(anyhow!("receipt status = {}, expected success", receipt.status));
    }
    if receipt.challenge_id != challenge_id {
        return Err(anyhow!(
            "receipt challengeId {} != challenge id {}",
            receipt.challenge_id,
            challenge_id
        ));
    }
    if receipt.settlement.currency != "sat" {
        return Err(anyhow!(
            "receipt settlement currency = {}",
            receipt.settlement.currency
        ));
    }
    let paid: u64 = receipt.settlement.amount.parse()?;
    if paid < AMOUNT_SATS {
        return Err(anyhow!(
            "receipt settled {paid} sat, expected >= {AMOUNT_SATS}"
        ));
    }
    println!(
        "[smoke]   200 ok; receipt method={} status={} settled={}{} timestamp={}",
        receipt.method,
        receipt.status,
        receipt.settlement.amount,
        receipt.settlement.currency,
        receipt.timestamp
    );
    println!("[smoke]   reference (sha256 of token, hex) = {}", receipt.reference);
    println!("[smoke]   random_hex = {random_hex}");

    Ok(())
}
