//! Web Push delivery via VAPID (spec §8).
//!
//! We send *tickle* notifications with no encrypted payload: the push only
//! wakes the service worker, which then fetches the notification feed in-app.
//! This satisfies the §8 "payload privacy / minimal data, details fetched
//! in-app" requirement and avoids shipping an aes128gcm payload-encryption
//! implementation. Only the VAPID JWT (ES256) is required.

use crate::webauthn::{b64url_decode, b64url_encode};
use okr_core::model::PushSubscription;
use okr_core::{DomainError, DomainResult};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::json;
use worker::{Fetch, Headers, Method, Request, RequestInit};

/// Build a signed VAPID JWT for the given audience (the push endpoint origin).
fn vapid_jwt(audience: &str, private_key_b64: &str, subject: &str) -> DomainResult<String> {
    let header = b64url_encode(
        json!({ "alg": "ES256", "typ": "JWT" })
            .to_string()
            .as_bytes(),
    );
    let claims = json!({
        "aud": audience,
        "exp": (crate::now_ms() / 1000) + 12 * 60 * 60,
        "sub": subject,
    });
    let payload = b64url_encode(claims.to_string().as_bytes());
    let signing_input = format!("{header}.{payload}");

    let sk_bytes = b64url_decode(private_key_b64)?;
    let sk = SigningKey::from_slice(&sk_bytes)
        .map_err(|_| DomainError::Internal("bad VAPID private key".into()))?;
    let sig: Signature = sk.sign(signing_input.as_bytes());
    let sig_b64 = b64url_encode(&sig.to_bytes());
    Ok(format!("{signing_input}.{sig_b64}"))
}

fn origin_of(endpoint: &str) -> Option<String> {
    let url = worker::Url::parse(endpoint).ok()?;
    Some(format!("{}://{}", url.scheme(), url.host_str()?))
}

/// Send a tickle push. Returns the HTTP status so the caller can prune dead
/// subscriptions on 404/410.
pub async fn send_tickle(
    sub: &PushSubscription,
    vapid_private_key_b64: &str,
    vapid_public_key_b64: &str,
    subject: &str,
) -> DomainResult<u16> {
    let audience = origin_of(&sub.endpoint)
        .ok_or_else(|| DomainError::Internal("bad push endpoint".into()))?;
    let jwt = vapid_jwt(&audience, vapid_private_key_b64, subject)?;

    let headers = Headers::new();
    let _ = headers.set("TTL", "60");
    let _ = headers.set(
        "Authorization",
        &format!("vapid t={jwt}, k={vapid_public_key_b64}"),
    );

    let mut init = RequestInit::new();
    init.with_method(Method::Post).with_headers(headers);
    let req = Request::new_with_init(&sub.endpoint, &init)
        .map_err(|e| DomainError::Internal(format!("push req: {e}")))?;
    let resp = Fetch::Request(req)
        .send()
        .await
        .map_err(|e| DomainError::Internal(format!("push send: {e}")))?;
    Ok(resp.status_code())
}
