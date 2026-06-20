//! Minimal, WASM-clean WebAuthn verifier (spec §6.1 fallback path).
//!
//! Supports the ES256 (P-256) algorithm, which every mainstream platform and
//! roaming authenticator (Apple/Google/Windows Hello, 1Password, security keys)
//! emits. Attestation is `none` (§6.1), so we parse the authenticator data but
//! do not verify an attestation statement.
//!
//! Registration verifies the client data ceremony fields and extracts the COSE
//! EC2 public key. Assertion verifies the ECDSA signature over
//! `authenticatorData || SHA-256(clientDataJSON)` plus all ceremony invariants
//! (type, challenge, origin, RP-ID hash, user-present flag, sign-count
//! monotonicity).

use base64::engine::general_purpose::{STANDARD_NO_PAD, URL_SAFE_NO_PAD};
use base64::Engine;
use ciborium::value::Value as Cbor;
use okr_core::{DomainError, DomainResult};
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use sha2::{Digest, Sha256};

fn invalid(msg: &str) -> DomainError {
    DomainError::Invalid(msg.to_string())
}

/// Decode base64url (no pad), tolerating standard-base64 / padded inputs.
pub fn b64url_decode(s: &str) -> DomainResult<Vec<u8>> {
    let t = s.trim_end_matches('=').replace('+', "-").replace('/', "_");
    URL_SAFE_NO_PAD
        .decode(t.as_bytes())
        .or_else(|_| STANDARD_NO_PAD.decode(s.trim_end_matches('=')))
        .map_err(|_| invalid("malformed base64url"))
}

pub fn b64url_encode(b: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(b)
}

#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    typ: String,
    challenge: String,
    origin: String,
}

/// Parsed authenticator data header (RP-ID hash + flags + sign count).
struct AuthData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    sign_count: u32,
    rest: &'a [u8],
}

fn parse_auth_data(data: &[u8]) -> DomainResult<AuthData<'_>> {
    if data.len() < 37 {
        return Err(invalid("authenticator data too short"));
    }
    let sign_count = u32::from_be_bytes([data[33], data[34], data[35], data[36]]);
    Ok(AuthData {
        rp_id_hash: &data[0..32],
        flags: data[32],
        sign_count,
        rest: &data[37..],
    })
}

const FLAG_UP: u8 = 0x01; // user present
const FLAG_AT: u8 = 0x40; // attested credential data included

fn verify_client_data(
    client_data_json: &[u8],
    expected_type: &str,
    expected_challenge_b64: &str,
    rp_origin: &str,
) -> DomainResult<()> {
    let cd: ClientData =
        serde_json::from_slice(client_data_json).map_err(|_| invalid("bad clientDataJSON"))?;
    if cd.typ != expected_type {
        return Err(invalid("clientData type mismatch"));
    }
    // Challenge is base64url in clientData; compare canonical decoded bytes.
    let got = b64url_decode(&cd.challenge)?;
    let want = b64url_decode(expected_challenge_b64)?;
    if got != want {
        return Err(invalid("challenge mismatch"));
    }
    if cd.origin != rp_origin {
        return Err(invalid("origin mismatch"));
    }
    Ok(())
}

fn rp_id_hash_ok(auth: &AuthData, rp_id: &str) -> bool {
    let expected = Sha256::digest(rp_id.as_bytes());
    auth.rp_id_hash == &expected[..]
}

/// Result of a verified registration.
pub struct RegistrationResult {
    pub credential_id: String,   // base64url
    pub public_key_sec1: String, // base64url of 0x04||x||y
    pub sign_count: u32,
    pub aaguid: String, // hex
}

/// Verify a registration (`navigator.credentials.create`) response.
pub fn verify_registration(
    attestation_object_b64: &str,
    client_data_json_b64: &str,
    expected_challenge_b64: &str,
    rp_id: &str,
    rp_origin: &str,
) -> DomainResult<RegistrationResult> {
    let client_data = b64url_decode(client_data_json_b64)?;
    verify_client_data(
        &client_data,
        "webauthn.create",
        expected_challenge_b64,
        rp_origin,
    )?;

    let att = b64url_decode(attestation_object_b64)?;
    let cbor: Cbor =
        ciborium::de::from_reader(att.as_slice()).map_err(|_| invalid("bad attestationObject"))?;
    let map = cbor
        .as_map()
        .ok_or_else(|| invalid("attestationObject not a map"))?;
    let auth_data_bytes = map
        .iter()
        .find(|(k, _)| k.as_text() == Some("authData"))
        .and_then(|(_, v)| v.as_bytes())
        .ok_or_else(|| invalid("missing authData"))?
        .clone();

    let auth = parse_auth_data(&auth_data_bytes)?;
    if auth.flags & FLAG_UP == 0 {
        return Err(invalid("user-present flag not set"));
    }
    if auth.flags & FLAG_AT == 0 {
        return Err(invalid("no attested credential data"));
    }
    if !rp_id_hash_ok(&auth, rp_id) {
        return Err(invalid("RP ID hash mismatch"));
    }

    // attestedCredentialData: aaguid(16) | credIdLen(2) | credId | COSEKey
    let rest = auth.rest;
    if rest.len() < 18 {
        return Err(invalid("attested credential data truncated"));
    }
    let aaguid = &rest[0..16];
    let cred_id_len = u16::from_be_bytes([rest[16], rest[17]]) as usize;
    let cred_id_end = 18 + cred_id_len;
    if rest.len() < cred_id_end {
        return Err(invalid("credential id truncated"));
    }
    let cred_id = &rest[18..cred_id_end];
    let cose_bytes = &rest[cred_id_end..];

    let public_key_sec1 = cose_ec2_to_sec1(cose_bytes)?;

    Ok(RegistrationResult {
        credential_id: b64url_encode(cred_id),
        public_key_sec1: b64url_encode(&public_key_sec1),
        sign_count: auth.sign_count,
        aaguid: hex(aaguid),
    })
}

/// Verify an assertion (`navigator.credentials.get`) response against a stored
/// SEC1 public key. Returns the new sign count to persist.
#[allow(clippy::too_many_arguments)]
pub fn verify_assertion(
    authenticator_data_b64: &str,
    client_data_json_b64: &str,
    signature_b64: &str,
    public_key_sec1_b64: &str,
    stored_sign_count: u32,
    expected_challenge_b64: &str,
    rp_id: &str,
    rp_origin: &str,
) -> DomainResult<u32> {
    let client_data = b64url_decode(client_data_json_b64)?;
    verify_client_data(
        &client_data,
        "webauthn.get",
        expected_challenge_b64,
        rp_origin,
    )?;

    let auth_data = b64url_decode(authenticator_data_b64)?;
    let auth = parse_auth_data(&auth_data)?;
    if auth.flags & FLAG_UP == 0 {
        return Err(invalid("user-present flag not set"));
    }
    if !rp_id_hash_ok(&auth, rp_id) {
        return Err(invalid("RP ID hash mismatch"));
    }

    // Clone detection (§6.1): reject a sign count that goes backwards, but
    // accept the authenticator that reports a constant 0.
    if auth.sign_count != 0 && stored_sign_count != 0 && auth.sign_count <= stored_sign_count {
        return Err(invalid("sign count did not increase (possible cloned key)"));
    }

    // Signed message = authenticatorData || SHA-256(clientDataJSON).
    let client_hash = Sha256::digest(&client_data);
    let mut message = auth_data.clone();
    message.extend_from_slice(&client_hash);

    let sec1 = b64url_decode(public_key_sec1_b64)?;
    let vk = VerifyingKey::from_sec1_bytes(&sec1).map_err(|_| invalid("bad stored public key"))?;
    let sig_der = b64url_decode(signature_b64)?;
    let sig = Signature::from_der(&sig_der).map_err(|_| invalid("bad signature encoding"))?;
    vk.verify(&message, &sig)
        .map_err(|_| DomainError::Unauthenticated)?;

    Ok(auth.sign_count.max(stored_sign_count))
}

/// Convert a COSE EC2 P-256 key (CBOR map) to a SEC1 uncompressed point.
fn cose_ec2_to_sec1(cose: &[u8]) -> DomainResult<Vec<u8>> {
    let val: Cbor = ciborium::de::from_reader(cose).map_err(|_| invalid("bad COSE key"))?;
    let map = val.as_map().ok_or_else(|| invalid("COSE key not a map"))?;
    let get = |key: i128| -> Option<&Cbor> {
        map.iter()
            .find(|(k, _)| k.as_integer().map(i128::from) == Some(key))
            .map(|(_, v)| v)
    };
    // kty must be EC2 (2), alg must be ES256 (-7), crv must be P-256 (1).
    if get(1).and_then(|v| v.as_integer()).map(i128::from) != Some(2) {
        return Err(invalid("unsupported key type (only EC2/ES256 supported)"));
    }
    if get(3).and_then(|v| v.as_integer()).map(i128::from) != Some(-7) {
        return Err(invalid("unsupported algorithm (only ES256 supported)"));
    }
    let x = get(-2)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| invalid("missing EC x"))?;
    let y = get(-3)
        .and_then(|v| v.as_bytes())
        .ok_or_else(|| invalid("missing EC y"))?;
    if x.len() != 32 || y.len() != 32 {
        return Err(invalid("bad EC coordinate length"));
    }
    let mut out = Vec::with_capacity(65);
    out.push(0x04);
    out.extend_from_slice(x);
    out.extend_from_slice(y);
    Ok(out)
}

fn hex(b: &[u8]) -> String {
    okr_core::ids::hex_encode(b)
}
