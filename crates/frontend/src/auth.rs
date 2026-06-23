//! Passkey ceremonies (spec §6). Browser interop lives in `/webauthn.js`; this
//! module orchestrates the two-step server ceremony (options → verify).

use crate::api;
use js_sys::JSON;
use serde_json::Value;
use wasm_bindgen::prelude::*;

#[wasm_bindgen(module = "/webauthn.js")]
extern "C" {
    #[wasm_bindgen(js_name = register, catch)]
    async fn js_register(public_key: JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = login, catch)]
    async fn js_login(public_key: JsValue) -> Result<JsValue, JsValue>;
    #[wasm_bindgen(js_name = supported)]
    fn js_supported() -> bool;
}

pub fn passkeys_supported() -> bool {
    js_supported()
}

fn to_js(v: &Value) -> Result<JsValue, String> {
    JSON::parse(&v.to_string()).map_err(|_| "bad JSON".to_string())
}

fn from_js(v: JsValue) -> Result<Value, String> {
    let s = JSON::stringify(&v)
        .map_err(|_| "stringify failed".to_string())?
        .as_string()
        .ok_or("not a string")?;
    serde_json::from_str(&s).map_err(|e| e.to_string())
}

fn js_msg(v: JsValue) -> String {
    v.as_string()
        .or_else(|| JSON::stringify(&v).ok().and_then(|s| s.as_string()))
        .unwrap_or_else(|| "passkey operation failed or was cancelled".into())
}

/// First-admin bootstrap (§6.2): supply the setup secret, register a passkey.
pub async fn bootstrap(setup_secret: &str) -> Result<(), String> {
    let url = format!("{}/auth/bootstrap/options", api::BASE);
    let resp = gloo_net::http::Request::post(&url)
        .header("X-Setup-Secret", setup_secret)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !(200..300).contains(&resp.status()) {
        return Err(format!("setup rejected (HTTP {})", resp.status()));
    }
    let options: Value = resp.json().await.map_err(|e| e.to_string())?;
    finish_registration(&options, "/auth/bootstrap/verify").await
}

/// Redeem a registration code and enrol a passkey (§6.3).
pub async fn register_with_code(code: &str) -> Result<(), String> {
    let options = api::post(
        "/auth/register/options",
        serde_json::json!({ "code": code }),
    )
    .await
    .map_err(|(s, v)| format!("code rejected (HTTP {s}): {v}"))?;
    finish_registration(&options, "/auth/register/verify").await
}

async fn finish_registration(options: &Value, verify_path: &str) -> Result<(), String> {
    let challenge_id = options["challengeId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let public_key = to_js(&options["publicKey"])?;
    let cred = js_register(public_key).await.map_err(js_msg)?;
    let mut body = from_js(cred)?;
    body["challengeId"] = Value::String(challenge_id);
    api::post(verify_path, body)
        .await
        .map(|_| ())
        .map_err(|(s, v)| format!("registration failed (HTTP {s}): {v}"))
}

/// Discoverable (usernameless) login (§6.1).
pub async fn login() -> Result<(), String> {
    let options = api::post("/auth/login/options", Value::Null)
        .await
        .map_err(|(s, _)| format!("login init failed (HTTP {s})"))?;
    let challenge_id = options["challengeId"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let public_key = to_js(&options["publicKey"])?;
    let cred = js_login(public_key).await.map_err(js_msg)?;
    let mut body = from_js(cred)?;
    body["challengeId"] = Value::String(challenge_id);
    api::post("/auth/login/verify", body)
        .await
        .map(|_| ())
        .map_err(|(s, _)| format!("login failed (HTTP {s})"))
}
