//! Thin JSON API client over `fetch` (gloo-net). Same-origin requests carry the
//! session cookie automatically; the browser sets `Sec-Fetch-Site` for the
//! server's CSRF check (spec §9).

use gloo_net::http::Request;
use serde_json::Value;

pub const BASE: &str = "/api/v1";

/// Perform a JSON request. On success returns the parsed body. On failure
/// returns `(status, error_body)`.
pub async fn call(method: &str, path: &str, body: Option<Value>) -> Result<Value, (u16, Value)> {
    let url = format!("{BASE}{path}");
    let builder = match method {
        "GET" => Request::get(&url),
        "POST" => Request::post(&url),
        "PATCH" => Request::patch(&url),
        "PUT" => Request::put(&url),
        "DELETE" => Request::delete(&url),
        _ => Request::get(&url),
    };
    let req = match body {
        Some(b) => builder
            .json(&b)
            .map_err(|e| (0, json_err(&e.to_string())))?,
        None => builder.build().map_err(|e| (0, json_err(&e.to_string())))?,
    };
    let resp = req
        .send()
        .await
        .map_err(|e| (0, json_err(&e.to_string())))?;
    let status = resp.status();
    let val: Value = resp.json().await.unwrap_or(Value::Null);
    if (200..300).contains(&status) {
        Ok(val)
    } else {
        Err((status, val))
    }
}

fn json_err(msg: &str) -> Value {
    serde_json::json!({ "error": "network", "detail": msg })
}

pub async fn get(path: &str) -> Result<Value, (u16, Value)> {
    call("GET", path, None).await
}
pub async fn post(path: &str, body: Value) -> Result<Value, (u16, Value)> {
    call("POST", path, Some(body)).await
}
