//! Smoke test for the cashu-mpp server.
//!
//! Mints 10 sats from `testnut.cashu.space` via the cdk crate, then drives both
//! legs of the NUT-24 flow against a server expected to be running on :3000.
//!
//! Run order:
//!     terminal A:  cargo run
//!     terminal B:  cargo run --example smoke
//!
//! Requires a working internet connection (and testnut.cashu.space must be up).

use std::process::ExitCode;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use cdk::amount::{Amount, SplitTarget};
use cdk::mint_url::MintUrl;
use cdk::nuts::{CurrencyUnit, MintQuoteState, PaymentMethod};
use cdk::wallet::{SendOptions, WalletBuilder};
use rand::Rng;
use serde_json::Value;

const MINT_URL: &str = "https://testnut.cashu.space";
const SERVER_URL: &str = "http://127.0.0.1:3000/random?bits=128";
const AMOUNT_SATS: u64 = 10;
const MINT_POLL_INTERVAL: Duration = Duration::from_millis(500);
const MINT_POLL_TIMEOUT: Duration = Duration::from_secs(20);

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

    println!("[smoke] step 2: request {AMOUNT_SATS}-sat mint quote");
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
    println!("[smoke]   quote_id={quote_id}");

    println!("[smoke] step 3: wait for testnut to auto-settle (faucet style)");
    let deadline = std::time::Instant::now() + MINT_POLL_TIMEOUT;
    loop {
        let q = wallet
            .check_mint_quote_status(&quote_id)
            .await
            .context("check_mint_quote_status")?;
        if q.state == MintQuoteState::Paid {
            println!("[smoke]   quote paid");
            break;
        }
        if std::time::Instant::now() > deadline {
            return Err(anyhow!(
                "timed out waiting for mint quote {quote_id} to be paid (state={:?})",
                q.state
            ));
        }
        tokio::time::sleep(MINT_POLL_INTERVAL).await;
    }

    println!("[smoke] step 4: mint proofs");
    let proofs = wallet
        .mint(&quote_id, SplitTarget::default(), None)
        .await
        .context("mint")?;
    let minted: u64 = proofs.iter().map(|p| u64::from(p.amount)).sum();
    println!("[smoke]   minted {minted} sat across {} proof(s)", proofs.len());

    println!("[smoke] step 5: encode cashuB token");
    let prepared = wallet
        .prepare_send(Amount::from(AMOUNT_SATS), SendOptions::default())
        .await
        .context("prepare_send")?;
    let token = prepared.confirm(None).await.context("confirm send")?;
    let token_str = token.to_string();
    let preview: String = token_str.chars().take(40).collect();
    println!("[smoke]   token = {preview}...  ({} chars)", token_str.len());

    println!("[smoke] step 6: GET {SERVER_URL} (no token, expect 402)");
    let client = reqwest::Client::new();
    let r1 = client.get(SERVER_URL).send().await.context("GET (no token)")?;
    let status = r1.status();
    let creq = r1
        .headers()
        .get("x-cashu")
        .ok_or_else(|| anyhow!("response missing X-Cashu header"))?
        .to_str()?
        .to_string();
    if status.as_u16() != 402 {
        return Err(anyhow!("expected 402, got {status}"));
    }
    println!("[smoke]   402 ok; X-Cashu starts with: {}", &creq[..creq.len().min(24)]);

    println!("[smoke] step 7: GET {SERVER_URL} with X-Cashu (expect 200)");
    let r2 = client
        .get(SERVER_URL)
        .header("X-Cashu", &token_str)
        .send()
        .await
        .context("GET (with token)")?;
    let status2 = r2.status();
    let body: Value = r2.json().await.context("parse json body")?;
    if status2.as_u16() != 200 {
        return Err(anyhow!("expected 200, got {status2}; body={body}"));
    }
    let random_hex = body
        .get("random_hex")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("body missing random_hex: {body}"))?;
    let amount_paid = body
        .get("amount_paid")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("body missing amount_paid: {body}"))?;
    let proofs_checked = body
        .get("proofs_checked")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("body missing proofs_checked: {body}"))?;

    println!(
        "[smoke]   200 ok; amount_paid={amount_paid} proofs_checked={proofs_checked} random_hex={random_hex}"
    );
    if random_hex.len() != 32 {
        return Err(anyhow!("expected 32 hex chars for 128 bits, got {}", random_hex.len()));
    }
    if amount_paid < AMOUNT_SATS {
        return Err(anyhow!("amount_paid {amount_paid} < {AMOUNT_SATS}"));
    }

    Ok(())
}
