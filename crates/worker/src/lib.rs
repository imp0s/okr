//! Cloudflare Worker entry point (spec §3.1 component 1). Stateless: it serves
//! the static SPA assets, applies security headers, and forwards `/api/*`
//! requests to the single `Org` Durable Object, which holds all mutable state.

mod config;
mod http;
mod org;
mod push;
mod sql;
mod webauthn;

pub use org::Org;

use worker::{Context, Env, Request, Response, Result};

/// Current epoch time in milliseconds (UTC). Used across the worker as the
/// single time source so behaviour is consistent within a request.
pub fn now_ms() -> i64 {
    worker::Date::now().as_millis() as i64
}

#[worker::event(fetch)]
async fn fetch(req: Request, env: Env, _ctx: Context) -> Result<Response> {
    console_error_panic_hook::set_once();

    let path = req.path();
    let mut resp = if path.starts_with("/api/") {
        // Route all stateful operations through the single Org DO instance.
        let namespace = env.durable_object("ORG")?;
        let stub = namespace.get_by_name("org")?;
        stub.fetch_with_request(req).await?
    } else {
        // Static assets (content-hashed, immutable) with SPA fallback handled
        // by the [assets] config in wrangler.toml.
        match env.assets("ASSETS") {
            Ok(assets) => assets.fetch_request(req).await?,
            Err(_) => Response::error("assets binding unavailable", 500)?,
        }
    };

    http::apply_security_headers(&mut resp);
    Ok(resp)
}
