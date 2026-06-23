//! Deployment configuration read from Worker bindings (vars + secrets).
//! See `docs/SECRETS.md` for provenance of every value.

use worker::{Env, Result};

pub struct Config {
    pub rp_id: String,
    pub rp_origin: String,
    pub setup_secret: String,
    pub vapid_public_key: String,
    pub vapid_private_key: String,
}

impl Config {
    /// Read configuration from the environment. Secrets fall back to `var` so a
    /// single accessor works whether a value was bound as a secret or a plain
    /// var (previews may inject some as vars).
    pub fn load(env: &Env) -> Result<Self> {
        Ok(Config {
            rp_id: get(env, "RP_ID")?,
            rp_origin: get(env, "RP_ORIGIN")?,
            setup_secret: get_secret(env, "SETUP_SECRET").unwrap_or_default(),
            vapid_public_key: get(env, "VAPID_PUBLIC_KEY").unwrap_or_default(),
            vapid_private_key: get_secret(env, "VAPID_PRIVATE_KEY").unwrap_or_default(),
        })
    }
}

fn get(env: &Env, name: &str) -> Result<String> {
    if let Ok(v) = env.var(name) {
        return Ok(v.to_string());
    }
    env.secret(name).map(|s| s.to_string())
}

fn get_secret(env: &Env, name: &str) -> Option<String> {
    env.secret(name)
        .map(|s| s.to_string())
        .ok()
        .or_else(|| env.var(name).map(|v| v.to_string()).ok())
}
