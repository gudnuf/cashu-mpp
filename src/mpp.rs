//! MPP (Machine Payments Protocol) wire format.
//!
//! Implements the HTTP 402 transport from <https://mpp.dev>: WWW-Authenticate /
//! Authorization / Payment-Receipt headers, JCS-canonicalized payment requests
//! and opaque blobs, and HMAC-SHA-256 challenge binding so the server is
//! stateless across the 402 → retry round-trip.
//!
//! The challenge `id` is `base64url(HMAC-SHA-256(secret, realm|method|intent|request|expires|digest|opaque))`
//! with empty string for absent slots and U+007C pipe bytes as the separator.
//! That means the server holds only the HMAC key — challenges live in the wire
//! values themselves, echoed back unchanged by the client per the spec.

use anyhow::{anyhow, bail, Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, KeyInit, Mac};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// 32-byte secret used to HMAC-bind challenge IDs. Generated once at startup.
#[derive(Clone)]
pub struct HmacKey(pub [u8; 32]);

/// MPP challenge — exactly the parameters the server emits in
/// `WWW-Authenticate: Payment ...` and the client echoes back.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    pub realm: String,
    pub method: String,
    pub intent: String,
    /// Base64url(JCS-JSON) of the method-specific request blob.
    pub request: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub expires: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub digest: Option<String>,
    /// Base64url(JCS-JSON) of server-defined correlation data. Client MUST echo unchanged.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub opaque: Option<String>,
}

impl Challenge {
    /// Compute the bound `id` for this challenge.
    pub fn bound_id(&self, key: &HmacKey) -> String {
        let canonical = canonical_input(self);
        let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC key length");
        mac.update(canonical.as_bytes());
        let tag = mac.finalize().into_bytes();
        URL_SAFE_NO_PAD.encode(tag)
    }

    /// Render a single `WWW-Authenticate: Payment ...` header value.
    pub fn auth_header_value(&self, key: &HmacKey) -> String {
        let id = self.bound_id(key);
        let mut parts: Vec<String> = vec![
            format!("id=\"{}\"", id),
            format!("realm=\"{}\"", self.realm),
            format!("method=\"{}\"", self.method),
            format!("intent=\"{}\"", self.intent),
            format!("request=\"{}\"", self.request),
        ];
        if let Some(e) = &self.expires {
            parts.push(format!("expires=\"{}\"", e));
        }
        if let Some(d) = &self.digest {
            parts.push(format!("digest=\"{}\"", d));
        }
        if let Some(o) = &self.opaque {
            parts.push(format!("opaque=\"{}\"", o));
        }
        format!("Payment {}", parts.join(", "))
    }

    /// Verify the claimed `id` was produced by HMAC-ing these challenge fields with `key`.
    pub fn verify_id(&self, key: &HmacKey, claimed_id: &str) -> Result<()> {
        let expected = self.bound_id(key);
        if constant_time_eq(expected.as_bytes(), claimed_id.as_bytes()) {
            Ok(())
        } else {
            bail!("challenge id does not match HMAC binding")
        }
    }

    /// Parse a `WWW-Authenticate: Payment id="...", ...` value.
    /// Returns `(id, challenge)` — id is wire-only; the challenge fields are
    /// what the client must echo back unchanged in the credential.
    pub fn parse_www_authenticate(value: &str) -> Result<(String, Self)> {
        let rest = value
            .strip_prefix("Payment ")
            .or_else(|| value.strip_prefix("payment "))
            .ok_or_else(|| anyhow!("WWW-Authenticate must use Payment scheme"))?;

        let mut params = std::collections::HashMap::new();
        for part in split_auth_params(rest) {
            let (name, raw_value) = part
                .split_once('=')
                .ok_or_else(|| anyhow!("auth-param missing '=' in {part:?}"))?;
            let name = name.trim().to_ascii_lowercase();
            let v = raw_value.trim();
            let unquoted = if v.starts_with('"') && v.ends_with('"') && v.len() >= 2 {
                v[1..v.len() - 1].to_string()
            } else {
                v.to_string()
            };
            params.insert(name, unquoted);
        }

        let take = |k: &str| {
            params
                .get(k)
                .cloned()
                .ok_or_else(|| anyhow!("missing required auth-param: {k}"))
        };
        let id = take("id")?;
        let challenge = Challenge {
            realm: take("realm")?,
            method: take("method")?,
            intent: take("intent")?,
            request: take("request")?,
            expires: params.get("expires").cloned(),
            digest: params.get("digest").cloned(),
            opaque: params.get("opaque").cloned(),
        };
        Ok((id, challenge))
    }
}

/// Split an auth-params list on commas that aren't inside quoted-strings.
fn split_auth_params(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_quotes = false;
    let mut cur = String::new();
    for c in s.chars() {
        match c {
            '"' => {
                in_quotes = !in_quotes;
                cur.push(c);
            }
            ',' if !in_quotes => {
                out.push(cur.trim().to_string());
                cur.clear();
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

fn canonical_input(c: &Challenge) -> String {
    [
        c.realm.as_str(),
        c.method.as_str(),
        c.intent.as_str(),
        c.request.as_str(),
        c.expires.as_deref().unwrap_or(""),
        c.digest.as_deref().unwrap_or(""),
        c.opaque.as_deref().unwrap_or(""),
    ]
    .join("|")
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// MPP credential carried in `Authorization: Payment <base64url(JSON)>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub challenge: Challenge,
    /// The bound challenge id the client picked. The server recomputes HMAC and rejects on mismatch.
    pub id: String,
    pub source: String,
    pub payload: serde_json::Value,
}

impl Credential {
    /// Encode for transport in the `Authorization` header value.
    pub fn to_auth_header_value(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(format!("Payment {}", URL_SAFE_NO_PAD.encode(json)))
    }

    /// Parse from an `Authorization` header value.
    pub fn from_auth_header_value(value: &str) -> Result<Self> {
        let rest = value
            .strip_prefix("Payment ")
            .or_else(|| value.strip_prefix("payment "))
            .ok_or_else(|| anyhow!("Authorization must use Payment scheme"))?;
        let json = URL_SAFE_NO_PAD
            .decode(rest.trim().as_bytes())
            .context("base64url decode credential")?;
        let cred: Credential = serde_json::from_slice(&json).context("credential JSON")?;
        Ok(cred)
    }

    /// Verify the echoed challenge id matches HMAC over the echoed challenge fields.
    pub fn verify_binding(&self, key: &HmacKey) -> Result<()> {
        self.challenge.verify_id(key, &self.id)
    }

    /// Verify the challenge has not expired (when `expires` is set).
    pub fn verify_not_expired(&self, now: chrono::DateTime<chrono::Utc>) -> Result<()> {
        let Some(exp_str) = &self.challenge.expires else {
            return Ok(());
        };
        let exp = chrono::DateTime::parse_from_rfc3339(exp_str)
            .with_context(|| format!("parse expires={exp_str}"))?
            .with_timezone(&chrono::Utc);
        if now > exp {
            bail!("challenge expired at {exp_str}");
        }
        Ok(())
    }
}

/// MPP receipt sent in the `Payment-Receipt` response header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Receipt {
    #[serde(rename = "challengeId")]
    pub challenge_id: String,
    pub method: String,
    pub reference: String,
    pub settlement: Settlement,
    pub status: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settlement {
    pub amount: String,
    pub currency: String,
}

impl Receipt {
    pub fn to_header_value(&self) -> Result<String> {
        let json = serde_json::to_vec(self)?;
        Ok(URL_SAFE_NO_PAD.encode(json))
    }
}

/// JCS-canonicalize a serializable value and base64url-encode.
pub fn encode_jcs_b64<T: Serialize>(value: &T) -> Result<String> {
    let canonical = serde_jcs::to_vec(value).context("JCS encode")?;
    Ok(URL_SAFE_NO_PAD.encode(canonical))
}

/// Reverse of `encode_jcs_b64`: base64url-decode then JSON-deserialize.
pub fn decode_jcs_b64<T: DeserializeOwned>(b64: &str) -> Result<T> {
    let bytes = URL_SAFE_NO_PAD
        .decode(b64.as_bytes())
        .context("base64url decode")?;
    let v: T = serde_json::from_slice(&bytes).context("JSON decode")?;
    Ok(v)
}

/// Generate a fresh 32-byte HMAC key.
pub fn fresh_hmac_key() -> HmacKey {
    use rand::Rng;
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    HmacKey(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_key() -> HmacKey {
        HmacKey([42u8; 32])
    }

    #[test]
    fn round_trip_challenge_id() {
        let c = Challenge {
            realm: "cashu-mpp".to_string(),
            method: "cashu".to_string(),
            intent: "charge".to_string(),
            request: "AAA".to_string(),
            expires: Some("2099-01-01T00:00:00Z".to_string()),
            digest: None,
            opaque: Some("BBB".to_string()),
        };
        let id = c.bound_id(&fixed_key());
        c.verify_id(&fixed_key(), &id).unwrap();

        // tamper with one field → fails
        let mut c2 = c.clone();
        c2.intent = "session".to_string();
        assert!(c2.verify_id(&fixed_key(), &id).is_err());
    }

    #[test]
    fn empty_slots_are_distinct() {
        let a = Challenge {
            realm: "r".into(),
            method: "m".into(),
            intent: "i".into(),
            request: "req".into(),
            expires: None,
            digest: None,
            opaque: None,
        };
        let mut b = a.clone();
        b.opaque = Some("".into());
        // both bind to the same canonical string (empty == None for canonical input)
        assert_eq!(a.bound_id(&fixed_key()), b.bound_id(&fixed_key()));
    }

    #[test]
    fn credential_round_trip() {
        let c = Challenge {
            realm: "cashu-mpp".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: "AAA".into(),
            expires: None,
            digest: None,
            opaque: None,
        };
        let id = c.bound_id(&fixed_key());
        let cred = Credential {
            challenge: c,
            id: id.clone(),
            source: "anonymous".into(),
            payload: serde_json::json!({ "token": "cashuB..." }),
        };
        let hdr = cred.to_auth_header_value().unwrap();
        let parsed = Credential::from_auth_header_value(&hdr).unwrap();
        parsed.verify_binding(&fixed_key()).unwrap();
        assert_eq!(parsed.id, id);
    }

    #[test]
    fn www_authenticate_round_trip() {
        let c = Challenge {
            realm: "cashu-mpp".into(),
            method: "cashu".into(),
            intent: "charge".into(),
            request: "AAA".into(),
            expires: Some("2099-01-01T00:00:00Z".into()),
            digest: None,
            opaque: Some("BBB".into()),
        };
        let hdr = c.auth_header_value(&fixed_key());
        let (id, parsed) = Challenge::parse_www_authenticate(&hdr).unwrap();
        assert_eq!(id, c.bound_id(&fixed_key()));
        parsed.verify_id(&fixed_key(), &id).unwrap();
        assert_eq!(parsed.realm, c.realm);
        assert_eq!(parsed.opaque, c.opaque);
    }

    #[test]
    fn jcs_b64_round_trip() {
        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct V {
            b: i32,
            a: String,
        }
        let v = V {
            b: 7,
            a: "x".into(),
        };
        let encoded = encode_jcs_b64(&v).unwrap();
        let decoded: V = decode_jcs_b64(&encoded).unwrap();
        assert_eq!(v, decoded);
    }
}
