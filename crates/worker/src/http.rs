//! HTTP plumbing shared by the entry Worker and the Org Durable Object:
//! security headers (§11), cookie handling (§6.4), CSRF / origin checks (§9),
//! and JSON/error response helpers.

use okr_core::DomainError;
use worker::{Headers, Response, Result};

pub const SESSION_COOKIE: &str = "okr_session";

/// Build the strict security header set (spec §11) and apply it to `resp`.
/// `connect_src` / `img_src` are tuned for the app: same-origin API + external
/// image references (https) only.
pub fn apply_security_headers(resp: &mut Response) {
    let h = resp.headers_mut();
    // Content Security Policy: no inline scripts; wasm needs wasm-unsafe-eval.
    let csp = "default-src 'self'; \
               script-src 'self' 'wasm-unsafe-eval'; \
               style-src 'self' 'unsafe-inline'; \
               img-src 'self' https: data:; \
               connect-src 'self'; \
               font-src 'self'; \
               manifest-src 'self'; \
               worker-src 'self'; \
               base-uri 'none'; \
               form-action 'none'; \
               frame-ancestors 'none'; \
               object-src 'none'";
    let _ = h.set("Content-Security-Policy", csp);
    let _ = h.set(
        "Strict-Transport-Security",
        "max-age=31536000; includeSubDomains; preload",
    );
    let _ = h.set("X-Content-Type-Options", "nosniff");
    let _ = h.set("Referrer-Policy", "no-referrer");
    let _ = h.set("X-Frame-Options", "DENY");
    let _ = h.set(
        "Permissions-Policy",
        "accelerometer=(), camera=(), geolocation=(), gyroscope=(), microphone=(), payment=(), usb=()",
    );
    let _ = h.set("Cross-Origin-Opener-Policy", "same-origin");
}

/// JSON success response.
pub fn json<T: serde::Serialize>(value: &T) -> Result<Response> {
    Response::from_json(value)
}

/// Map a domain error to the appropriate HTTP status and JSON body.
pub fn error_response(err: &DomainError) -> Result<Response> {
    let status = match err {
        DomainError::Unauthenticated => 401,
        DomainError::Forbidden => 403,
        DomainError::NotFound(_) => 404,
        DomainError::Invalid(_) => 400,
        DomainError::Conflict(_) | DomainError::SetupClosed => 409,
        DomainError::BadRegistrationCode => 400,
        DomainError::RateLimited => 429,
        DomainError::Internal(_) => 500,
    };
    Ok(Response::from_json(err)?.with_status(status))
}

/// Parse a named cookie value from a `Cookie` header.
pub fn cookie(headers: &Headers, name: &str) -> Option<String> {
    let raw = headers.get("Cookie").ok().flatten()?;
    raw.split(';')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| k.trim() == name)
        .map(|(_, v)| v.trim().to_string())
}

/// `Set-Cookie` value for a fresh session (§6.4 cookie attributes).
pub fn set_session_cookie(id: &str, max_age_secs: i64) -> String {
    format!(
        "{SESSION_COOKIE}={id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age_secs}"
    )
}

/// `Set-Cookie` value that clears the session cookie.
pub fn clear_session_cookie() -> String {
    format!("{SESSION_COOKIE}=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0")
}

/// CSRF defence for state-changing requests (§9, §11): require a same-origin
/// `Origin` (matching the configured RP origin) or a same-origin
/// `Sec-Fetch-Site`. Returns `true` if the request is allowed.
pub fn is_same_site(headers: &Headers, rp_origin: &str) -> bool {
    if let Ok(Some(site)) = headers.get("Sec-Fetch-Site") {
        // Browsers that send this header: only same-origin/none are accepted.
        return site == "same-origin" || site == "none";
    }
    // Fall back to an explicit Origin check.
    match headers.get("Origin") {
        Ok(Some(origin)) => origin == rp_origin,
        _ => false, // fail closed when neither header is present on a mutation
    }
}
