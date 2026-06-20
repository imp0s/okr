//! The `Org` Durable Object: the single source of truth (spec §3.1/§3.3). It
//! owns the SQLite store, runs the API router for all `/api/v1/*` endpoints,
//! validates sessions, enforces authorization via `okr-core`, and emits
//! notifications. All mutations are serialised here, giving the strong
//! consistency the versioning / ref-uniqueness / session-invalidation rules
//! require.

use crate::config::Config;
use crate::http::{self, SESSION_COOKIE};
use crate::sql::SqlStore;
use crate::{now_ms, push, webauthn};
use okr_core::authz::{require, Capability};
use okr_core::code::{validate_reg_code, verify_setup_secret, REG_CODE_TTL_MS, SESSION_TTL_MS};
use okr_core::done::effective_done;
use okr_core::ids::{self, RefKind};
use okr_core::model::*;
use okr_core::storage::Storage;
use okr_core::versioning::VersionState;
use okr_core::{markdown, DomainError, DomainResult};
use serde_json::{json, Value};
use std::cell::Cell;
use std::collections::BTreeSet;
use worker::{DurableObject, Env, Request, Response, Result, State};

const CHALLENGE_TTL_MS: i64 = 5 * 60 * 1000;
/// Auth/registration endpoints are rate limited per-window (§11).
const RL_WINDOW_MS: i64 = 60 * 1000;
const RL_MAX_HITS: u32 = 30;

#[worker::durable_object]
pub struct Org {
    state: State,
    env: Env,
    initialized: Cell<bool>,
}

impl DurableObject for Org {
    fn new(state: State, env: Env) -> Self {
        Org {
            state,
            env,
            initialized: Cell::new(false),
        }
    }

    async fn fetch(&self, mut req: Request) -> Result<Response> {
        let store = SqlStore::new(self.state.storage().sql());
        if !self.initialized.get() {
            if let Err(e) = store.ensure_schema() {
                return http::error_response(&e);
            }
            self.initialized.set(true);
        }
        let cfg = match Config::load(&self.env) {
            Ok(c) => c,
            Err(e) => return Response::error(format!("config error: {e}"), 500),
        };

        match route(&store, &cfg, &mut req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                if let DomainError::Internal(detail) = &e {
                    worker::console_error!("internal error: {detail}");
                }
                http::error_response(&e)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

async fn route(store: &SqlStore, cfg: &Config, req: &mut Request) -> DomainResult<Response> {
    let method = req.method();
    let path = req.path();
    let segs: Vec<&str> = path
        .trim_start_matches("/api/v1/")
        .trim_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();

    // CSRF / origin check on every state-changing request (§9, §11).
    let is_mutation = !matches!(method, worker::Method::Get | worker::Method::Head);
    if is_mutation && !http::is_same_site(req.headers(), &cfg.rp_origin) {
        return Err(DomainError::Forbidden);
    }

    let body = if is_mutation {
        let t = req.text().await.unwrap_or_default();
        if t.len() > 200_000 {
            return Err(DomainError::Invalid("request body too large".into()));
        }
        serde_json::from_str::<Value>(&t).unwrap_or(Value::Null)
    } else {
        Value::Null
    };

    use worker::Method::*;
    let s: Vec<&str> = segs.clone();
    match (method.clone(), s.as_slice()) {
        // ---- auth ----------------------------------------------------------
        (Post, ["auth", "bootstrap", "options"]) => bootstrap_options(store, cfg, req).await,
        (Post, ["auth", "bootstrap", "verify"]) => bootstrap_verify(store, cfg, &body).await,
        (Post, ["auth", "register", "options"]) => register_options(store, cfg, &body).await,
        (Post, ["auth", "register", "verify"]) => register_verify(store, cfg, &body).await,
        (Post, ["auth", "login", "options"]) => login_options(store, cfg).await,
        (Post, ["auth", "login", "verify"]) => login_verify(store, cfg, &body).await,
        (Post, ["auth", "logout"]) => logout(store, req).await,
        (Get, ["me"]) => me(store, req).await,
        (Patch, ["me"]) => patch_me(store, req, &body).await,
        (Delete, ["me", "credentials", id]) => delete_my_credential(store, req, id).await,

        // ---- users (admin) -------------------------------------------------
        (Get, ["users"]) => list_users(store, req).await,
        (Post, ["users"]) => create_user(store, req, &body).await,
        (Patch, ["users", id]) => patch_user(store, req, id, &body).await,
        (Delete, ["users", id]) => delete_user(store, req, id).await,
        (Post, ["users", id, "code"]) => reissue_code(store, req, id).await,

        // ---- groups --------------------------------------------------------
        (Get, ["groups"]) => list_groups(store, req).await,
        (Post, ["groups"]) => create_group(store, req, &body).await,
        (Patch, ["groups", id]) => edit_group(store, req, id, &body).await,
        (Get, ["groups", id, "versions"]) => group_versions(store, req, id).await,
        (Post, ["groups", id, "revert"]) => revert_group(store, req, id, &body).await,
        (Delete, ["groups", id]) => delete_group(store, req, id).await,

        // ---- okrs ----------------------------------------------------------
        (Get, ["okrs"]) => list_okrs(store, req).await,
        (Post, ["okrs"]) => create_okr(store, req, &body).await,
        (Patch, ["okrs", id]) => edit_okr(store, cfg, req, id, &body).await,
        (Get, ["okrs", id, "versions"]) => okr_versions(store, req, id).await,
        (Post, ["okrs", id, "revert"]) => revert_okr(store, req, id, &body).await,
        (Delete, ["okrs", id]) => delete_okr(store, req, id).await,
        (Put, ["okrs", id, "assignees"]) => set_assignees(store, cfg, req, id, &body).await,
        (Put, ["okrs", id, "done"]) => set_done(store, req, id, &body).await,

        // ---- updates -------------------------------------------------------
        (Get, ["okrs", id, "updates"]) => list_updates(store, req, id).await,
        (Post, ["okrs", id, "updates"]) => post_update(store, cfg, req, id, &body).await,
        (Patch, ["updates", id]) => edit_update(store, req, id, &body).await,
        (Delete, ["updates", id]) => delete_update(store, req, id).await,

        // ---- notifications / push -----------------------------------------
        (Get, ["notifications"]) => list_notifications(store, req).await,
        (Post, ["notifications", "read"]) => read_notifications(store, req, &body).await,
        (Get, ["push", "vapid-public-key"]) => {
            http_json(&json!({ "publicKey": cfg.vapid_public_key }))
        }
        (Post, ["push", "subscribe"]) => push_subscribe(store, req, &body).await,
        (Delete, ["push", "subscribe"]) => push_unsubscribe(store, req, &body).await,

        _ => Err(DomainError::NotFound("route".into())),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn http_json<T: serde::Serialize>(v: &T) -> DomainResult<Response> {
    http::json(v).map_err(|e| DomainError::Internal(format!("serialise: {e}")))
}

fn str_field<'a>(body: &'a Value, key: &str) -> &'a str {
    body.get(key).and_then(|v| v.as_str()).unwrap_or("")
}

/// Resolve the authenticated actor from the session cookie, or `None`.
async fn authenticate(store: &SqlStore, req: &Request) -> DomainResult<Option<Actor>> {
    let Some(sid) = http::cookie(req.headers(), SESSION_COOKIE) else {
        return Ok(None);
    };
    let Some(session) = store.get_session(&sid).await? else {
        return Ok(None);
    };
    if session.expires_at <= now_ms() {
        store.delete_session(&sid).await?;
        return Ok(None);
    }
    let Some(user) = store.get_user(&session.user_id).await? else {
        // User deleted -> session is dead (§6.4 immediate invalidation).
        store.delete_session(&sid).await?;
        return Ok(None);
    };
    if user.status != UserStatus::Active {
        return Ok(None);
    }
    Ok(Some(Actor {
        user_id: user.id,
        is_admin: user.is_admin,
    }))
}

async fn require_actor(store: &SqlStore, req: &Request) -> DomainResult<Actor> {
    authenticate(store, req)
        .await?
        .ok_or(DomainError::Unauthenticated)
}

async fn rate_limit(store: &SqlStore, bucket: &str) -> DomainResult<()> {
    let hits = store.rate_limit_hit(bucket, RL_WINDOW_MS, now_ms()).await?;
    if hits > RL_MAX_HITS {
        Err(DomainError::RateLimited)
    } else {
        Ok(())
    }
}

async fn unique_human_ref(store: &SqlStore, kind: RefKind) -> DomainResult<String> {
    for _ in 0..20 {
        let r = ids::gen_human_ref(kind);
        if !store.human_ref_exists(&r).await? {
            return Ok(r);
        }
    }
    Err(DomainError::Internal("ref allocation failed".into()))
}

async fn unique_short_name(store: &SqlStore) -> DomainResult<String> {
    for _ in 0..20 {
        let sn = ids::gen_short_name();
        if !store.short_name_exists(&sn).await? {
            return Ok(sn);
        }
    }
    Err(DomainError::Internal("short_name allocation failed".into()))
}

fn random_challenge() -> String {
    let mut buf = [0u8; 32];
    ids::random_bytes(&mut buf);
    webauthn::b64url_encode(&buf)
}

fn version_state(current: u64, counter: u64, versions: &[u64]) -> VersionState {
    VersionState {
        current_version: current,
        next_version_counter: counter,
        valid_versions: versions.iter().copied().collect::<BTreeSet<_>>(),
    }
}

/// Create in-app notifications and fire best-effort tickle pushes (§8).
async fn notify(
    store: &SqlStore,
    cfg: &Config,
    user_ids: &[String],
    kind: NotificationKind,
    payload: Value,
) -> DomainResult<()> {
    for uid in user_ids {
        let n = Notification {
            id: ids::new_uuid(),
            user_id: uid.clone(),
            kind,
            payload: payload.clone(),
            created_at: now_ms(),
            read_at: None,
        };
        store.insert_notification(&n).await?;

        if cfg.vapid_private_key.is_empty() || cfg.vapid_public_key.is_empty() {
            continue;
        }
        for sub in store.list_push_subscriptions(uid).await? {
            match push::send_tickle(
                &sub,
                &cfg.vapid_private_key,
                &cfg.vapid_public_key,
                &format!("mailto:admin@{}", cfg.rp_id),
            )
            .await
            {
                Ok(404) | Ok(410) => {
                    let _ = store.delete_push_subscription(&sub.endpoint).await;
                }
                _ => {}
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Auth ceremonies
// ---------------------------------------------------------------------------

fn webauthn_create_options(
    challenge: &str,
    user_handle_b64: &str,
    short_name: &str,
    display_name: &str,
    rp_id: &str,
) -> Value {
    json!({
        "challenge": challenge,
        "rp": { "id": rp_id, "name": "OKR Tracker" },
        "user": { "id": user_handle_b64, "name": short_name, "displayName": display_name },
        "pubKeyCredParams": [{ "type": "public-key", "alg": -7 }],
        "authenticatorSelection": {
            "residentKey": "required",
            "requireResidentKey": true,
            "userVerification": "preferred"
        },
        "attestation": "none",
        "timeout": 120000
    })
}

async fn bootstrap_options(
    store: &SqlStore,
    cfg: &Config,
    req: &mut Request,
) -> DomainResult<Response> {
    rate_limit(store, "bootstrap").await?;
    if store.user_count().await? > 0 {
        return Err(DomainError::SetupClosed);
    }
    let provided = req
        .headers()
        .get("X-Setup-Secret")
        .ok()
        .flatten()
        .unwrap_or_default();
    verify_setup_secret(&provided, &cfg.setup_secret)?;

    let handle = ids::gen_webauthn_user_handle();
    let handle_b64 = webauthn::b64url_encode(&handle);
    let short_name = unique_short_name(store).await?;
    let challenge = random_challenge();
    let cid = ids::gen_session_id();
    let pending = json!({ "handle": handle_b64, "short_name": short_name, "is_admin": true });
    store.put_challenge(
        &cid,
        "bootstrap",
        &challenge,
        None,
        Some(&pending.to_string()),
        now_ms() + CHALLENGE_TTL_MS,
    )?;

    http_json(&json!({
        "challengeId": cid,
        "publicKey": webauthn_create_options(&challenge, &handle_b64, &short_name, "Administrator", &cfg.rp_id),
    }))
}

async fn bootstrap_verify(store: &SqlStore, cfg: &Config, body: &Value) -> DomainResult<Response> {
    if store.user_count().await? > 0 {
        return Err(DomainError::SetupClosed);
    }
    let ch = store
        .take_challenge(str_field(body, "challengeId"), now_ms())?
        .filter(|c| c.kind == "bootstrap")
        .ok_or(DomainError::Invalid("challenge expired".into()))?;
    let pending: Value = serde_json::from_str(&ch.data).unwrap_or(Value::Null);

    let reg = webauthn::verify_registration(
        str_field(body, "attestationObject"),
        str_field(body, "clientDataJSON"),
        &ch.challenge,
        &cfg.rp_id,
        &cfg.rp_origin,
    )?;

    let user = User {
        id: ids::new_uuid(),
        name: "Administrator".into(),
        short_name: str_field(&pending, "short_name").to_string(),
        webauthn_handle: str_field(&pending, "handle").to_string(),
        is_admin: true,
        status: UserStatus::Active,
        created_at: now_ms(),
    };
    store.insert_user(&user).await?;
    store_credential(store, &user.id, &reg).await?;
    finish_login(store, &user.id).await
}

async fn register_options(store: &SqlStore, cfg: &Config, body: &Value) -> DomainResult<Response> {
    rate_limit(store, "register").await?;
    let code = ids::normalise_code(str_field(body, "code"));
    let stored = store
        .get_reg_code(&code)
        .await?
        .ok_or(DomainError::BadRegistrationCode)?;
    validate_reg_code(&stored, &code, now_ms())?;
    let user = store
        .get_user(&stored.user_id)
        .await?
        .ok_or(DomainError::BadRegistrationCode)?;

    let challenge = random_challenge();
    let cid = ids::gen_session_id();
    store.put_challenge(
        &cid,
        "register",
        &challenge,
        Some(&user.id),
        Some(&json!({ "code": code }).to_string()),
        now_ms() + CHALLENGE_TTL_MS,
    )?;

    http_json(&json!({
        "challengeId": cid,
        "publicKey": webauthn_create_options(
            &challenge,
            &user.webauthn_handle,
            &user.short_name,
            &user.name,
            &cfg.rp_id,
        ),
    }))
}

async fn register_verify(store: &SqlStore, cfg: &Config, body: &Value) -> DomainResult<Response> {
    let ch = store
        .take_challenge(str_field(body, "challengeId"), now_ms())?
        .filter(|c| c.kind == "register")
        .ok_or(DomainError::Invalid("challenge expired".into()))?;
    let reg = webauthn::verify_registration(
        str_field(body, "attestationObject"),
        str_field(body, "clientDataJSON"),
        &ch.challenge,
        &cfg.rp_id,
        &cfg.rp_origin,
    )?;
    store_credential(store, &ch.user_id, &reg).await?;
    // Burn the code now that registration succeeded (single-use, §6.3).
    let data: Value = serde_json::from_str(&ch.data).unwrap_or(Value::Null);
    store
        .mark_code_used(str_field(&data, "code"), now_ms())
        .await?;
    finish_login(store, &ch.user_id).await
}

async fn login_options(store: &SqlStore, _cfg: &Config) -> DomainResult<Response> {
    rate_limit(store, "login").await?;
    let challenge = random_challenge();
    let cid = ids::gen_session_id();
    store.put_challenge(
        &cid,
        "login",
        &challenge,
        None,
        None,
        now_ms() + CHALLENGE_TTL_MS,
    )?;
    http_json(&json!({
        "challengeId": cid,
        "publicKey": {
            "challenge": challenge,
            "rpId": _cfg.rp_id,
            "userVerification": "preferred",
            "allowCredentials": [],
            "timeout": 120000
        }
    }))
}

async fn login_verify(store: &SqlStore, cfg: &Config, body: &Value) -> DomainResult<Response> {
    let ch = store
        .take_challenge(str_field(body, "challengeId"), now_ms())?
        .filter(|c| c.kind == "login")
        .ok_or(DomainError::Unauthenticated)?;
    let cred_id = str_field(body, "id");
    let cred = store
        .get_credential(cred_id)
        .await?
        .ok_or(DomainError::Unauthenticated)?;
    let new_count = webauthn::verify_assertion(
        str_field(body, "authenticatorData"),
        str_field(body, "clientDataJSON"),
        str_field(body, "signature"),
        &cred.public_key,
        cred.sign_count,
        &ch.challenge,
        &cfg.rp_id,
        &cfg.rp_origin,
    )?;
    let user = store
        .get_user(&cred.user_id)
        .await?
        .filter(|u| u.status == UserStatus::Active)
        .ok_or(DomainError::Unauthenticated)?;
    if new_count != cred.sign_count {
        store
            .update_credential_sign_count(&cred.id, new_count)
            .await?;
    }
    finish_login(store, &user.id).await
}

async fn store_credential(
    store: &SqlStore,
    user_id: &str,
    reg: &webauthn::RegistrationResult,
) -> DomainResult<()> {
    let cred = Credential {
        id: ids::new_uuid(),
        user_id: user_id.to_string(),
        webauthn_credential_id: reg.credential_id.clone(),
        public_key: reg.public_key_sec1.clone(),
        sign_count: reg.sign_count,
        aaguid: reg.aaguid.clone(),
        transports: vec![],
        created_at: now_ms(),
    };
    store.insert_credential(&cred).await
}

/// Create a session and return `{ ok: true }` with the session cookie set.
async fn finish_login(store: &SqlStore, user_id: &str) -> DomainResult<Response> {
    let session = Session {
        id: ids::gen_session_id(),
        user_id: user_id.to_string(),
        created_at: now_ms(),
        expires_at: now_ms() + SESSION_TTL_MS,
    };
    store.insert_session(&session).await?;
    let mut resp = http_json(&json!({ "ok": true }))?;
    let _ = resp.headers_mut().set(
        "Set-Cookie",
        &http::set_session_cookie(&session.id, SESSION_TTL_MS / 1000),
    );
    Ok(resp)
}

async fn logout(store: &SqlStore, req: &Request) -> DomainResult<Response> {
    if let Some(sid) = http::cookie(req.headers(), SESSION_COOKIE) {
        store.delete_session(&sid).await?;
    }
    let mut resp = http_json(&json!({ "ok": true }))?;
    let _ = resp
        .headers_mut()
        .set("Set-Cookie", &http::clear_session_cookie());
    Ok(resp)
}

async fn me(store: &SqlStore, req: &Request) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let user = store
        .get_user(&actor.user_id)
        .await?
        .ok_or(DomainError::Unauthenticated)?;
    let creds = store.list_credentials(&user.id).await?;
    http_json(&json!({
        "id": user.id,
        "name": user.name,
        "shortName": user.short_name,
        "isAdmin": user.is_admin,
        "credentials": creds.iter().map(|c| json!({
            "id": c.id, "aaguid": c.aaguid, "createdAt": c.created_at
        })).collect::<Vec<_>>(),
    }))
}

async fn patch_me(store: &SqlStore, req: &Request, body: &Value) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let mut user = store
        .get_user(&actor.user_id)
        .await?
        .ok_or(DomainError::Unauthenticated)?;
    user.name = ids::validate_display_name(str_field(body, "name"))?;
    store.update_user(&user).await?;
    http_json(&json!({ "ok": true }))
}

async fn delete_my_credential(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    store.delete_credential(id, &actor.user_id).await?;
    http_json(&json!({ "ok": true }))
}

// ---------------------------------------------------------------------------
// Users (admin)
// ---------------------------------------------------------------------------

fn user_json(u: &User) -> Value {
    json!({
        "id": u.id, "name": u.name, "shortName": u.short_name,
        "isAdmin": u.is_admin, "status": u.status, "createdAt": u.created_at
    })
}

async fn list_users(store: &SqlStore, req: &Request) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageUsers)?;
    let users = store.list_users().await?;
    http_json(&users.iter().map(user_json).collect::<Vec<_>>())
}

async fn create_user(store: &SqlStore, req: &Request, body: &Value) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageUsers)?;
    let name = ids::validate_display_name(str_field(body, "name"))?;
    let is_admin = body
        .get("isAdmin")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    let user = User {
        id: ids::new_uuid(),
        name,
        short_name: unique_short_name(store).await?,
        webauthn_handle: webauthn::b64url_encode(&ids::gen_webauthn_user_handle()),
        is_admin,
        status: UserStatus::Active,
        created_at: now_ms(),
    };
    store.insert_user(&user).await?;
    let code = issue_code(store, &user.id).await?;
    http_json(&json!({ "user": user_json(&user), "code": code }))
}

async fn issue_code(store: &SqlStore, user_id: &str) -> DomainResult<String> {
    store.invalidate_codes_for_user(user_id).await?;
    let display = ids::gen_registration_code();
    let rc = RegCode {
        code: ids::normalise_code(&display),
        user_id: user_id.to_string(),
        created_at: now_ms(),
        expires_at: now_ms() + REG_CODE_TTL_MS,
        used_at: None,
    };
    store.insert_reg_code(&rc).await?;
    Ok(display)
}

async fn patch_user(
    store: &SqlStore,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageUsers)?;
    let mut user = store
        .get_user(id)
        .await?
        .ok_or(DomainError::NotFound("user".into()))?;
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        user.name = ids::validate_display_name(name)?;
    }
    if let Some(is_admin) = body.get("isAdmin").and_then(|v| v.as_bool()) {
        user.is_admin = is_admin; // no last-admin safeguard by design (§7, Q10d)
    }
    store.update_user(&user).await?;
    http_json(&user_json(&user))
}

async fn delete_user(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageUsers)?;
    // Immediate session invalidation is handled by the cascade (§6.4).
    store.delete_user(id).await?;
    http_json(&json!({ "ok": true }))
}

async fn reissue_code(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageUsers)?;
    store
        .get_user(id)
        .await?
        .ok_or(DomainError::NotFound("user".into()))?;
    let code = issue_code(store, id).await?;
    http_json(&json!({ "code": code }))
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

fn group_json(g: &Group, v: &GroupVersion) -> Value {
    json!({
        "id": g.id, "humanRef": g.human_ref,
        "currentVersion": g.current_version, "createdAt": g.created_at,
        "name": v.name, "descriptionMd": v.description_md,
        "descriptionHtml": markdown::render(&v.description_md),
    })
}

async fn list_groups(store: &SqlStore, req: &Request) -> DomainResult<Response> {
    require_actor(store, req).await?;
    let groups = store.list_groups().await?;
    let mut out = Vec::new();
    for g in &groups {
        if let Some(v) = store.get_group_version(&g.id, g.current_version).await? {
            out.push(group_json(g, &v));
        }
    }
    http_json(&out)
}

async fn create_group(store: &SqlStore, req: &Request, body: &Value) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    let name = ids::validate_display_name(str_field(body, "name"))?;
    let desc = validate_md(str_field(body, "descriptionMd"))?;
    let outcome = VersionState::create();
    let group = Group {
        id: ids::new_uuid(),
        human_ref: unique_human_ref(store, RefKind::Group).await?,
        current_version: outcome.state.current_version,
        next_version_counter: outcome.state.next_version_counter,
        created_at: now_ms(),
    };
    let v = GroupVersion {
        group_id: group.id.clone(),
        version: outcome.new_version,
        name,
        description_md: desc,
        valid: true,
        author_id: actor.user_id.clone(),
        created_at: now_ms(),
    };
    store.insert_group(&group, &v).await?;
    http_json(&group_json(&group, &v))
}

async fn edit_group(
    store: &SqlStore,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    let mut group = store
        .get_group(id)
        .await?
        .ok_or(DomainError::NotFound("group".into()))?;
    let versions = store.list_group_versions(id).await?;
    let valid: Vec<u64> = versions
        .iter()
        .filter(|v| v.valid)
        .map(|v| v.version)
        .collect();
    let outcome = version_state(group.current_version, group.next_version_counter, &valid).edit();
    group.current_version = outcome.state.current_version;
    group.next_version_counter = outcome.state.next_version_counter;
    let v = GroupVersion {
        group_id: group.id.clone(),
        version: outcome.new_version,
        name: ids::validate_display_name(str_field(body, "name"))?,
        description_md: validate_md(str_field(body, "descriptionMd"))?,
        valid: true,
        author_id: actor.user_id.clone(),
        created_at: now_ms(),
    };
    store.put_group_version(&group, &v).await?;
    http_json(&group_json(&group, &v))
}

async fn group_versions(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    require_actor(store, req).await?;
    let versions = store.list_group_versions(id).await?;
    http_json(
        &versions
            .iter()
            .map(|v| {
                json!({
                    "version": v.version, "name": v.name, "descriptionMd": v.description_md,
                    "valid": v.valid, "authorId": v.author_id, "createdAt": v.created_at
                })
            })
            .collect::<Vec<_>>(),
    )
}

async fn revert_group(
    store: &SqlStore,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    let mut group = store
        .get_group(id)
        .await?
        .ok_or(DomainError::NotFound("group".into()))?;
    let target = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let versions = store.list_group_versions(id).await?;
    let valid: Vec<u64> = versions
        .iter()
        .filter(|v| v.valid)
        .map(|v| v.version)
        .collect();
    let outcome = version_state(group.current_version, group.next_version_counter, &valid)
        .revert_to(target)?;
    group.current_version = outcome.state.current_version;
    store.revert_group(&group, &outcome.burned).await?;
    http_json(
        &json!({ "ok": true, "currentVersion": group.current_version, "burned": outcome.burned }),
    )
}

async fn delete_group(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    store.delete_group(id).await?;
    http_json(&json!({ "ok": true }))
}

fn validate_md(md: &str) -> DomainResult<String> {
    if md.len() > markdown::MAX_MARKDOWN_LEN {
        return Err(DomainError::Invalid("markdown too long".into()));
    }
    Ok(md.to_string())
}

// ---------------------------------------------------------------------------
// OKRs
// ---------------------------------------------------------------------------

async fn okr_json(store: &SqlStore, o: &Okr, v: &OkrVersion) -> DomainResult<Value> {
    let assignees = store.list_assignees(&o.id).await?;
    let done_records = store.list_done(&o.id).await?;
    Ok(json!({
        "id": o.id, "humanRef": o.human_ref, "groupId": o.group_id,
        "currentVersion": o.current_version, "createdAt": o.created_at,
        "objectiveMd": v.objective_md, "objectiveHtml": markdown::render(&v.objective_md),
        "keyResultsMd": v.key_results_md, "keyResultsHtml": markdown::render(&v.key_results_md),
        "assignees": assignees,
        "done": effective_done(&done_records, o.current_version),
    }))
}

async fn list_okrs(store: &SqlStore, req: &Request) -> DomainResult<Response> {
    require_actor(store, req).await?;
    let url = req
        .url()
        .map_err(|e| DomainError::Internal(e.to_string()))?;
    let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();

    let okrs = store.list_okrs().await?;
    let mut out = Vec::new();
    for o in &okrs {
        if let Some(g) = q.get("group") {
            if &o.group_id != g {
                continue;
            }
        }
        let Some(v) = store.get_okr_version(&o.id, o.current_version).await? else {
            continue;
        };
        let mut item = okr_json(store, o, &v).await?;
        if let Some(assignee) = q.get("assignee") {
            let ok = item["assignees"]
                .as_array()
                .map(|a| a.iter().any(|x| x.as_str() == Some(assignee)))
                .unwrap_or(false);
            if !ok {
                continue;
            }
        }
        if let Some(done) = q.get("done") {
            let want = done == "true";
            if item["done"].as_bool().unwrap_or(false) != want {
                continue;
            }
        }
        if let Some(obj) = item.as_object_mut() {
            obj.insert("sortKey".into(), json!(o.created_at));
        }
        out.push(item);
    }
    http_json(&out)
}

async fn create_okr(store: &SqlStore, req: &Request, body: &Value) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    let group_id = str_field(body, "groupId");
    store
        .get_group(group_id)
        .await?
        .ok_or(DomainError::NotFound("group".into()))?;
    let outcome = VersionState::create();
    let okr = Okr {
        id: ids::new_uuid(),
        human_ref: unique_human_ref(store, RefKind::Okr).await?,
        group_id: group_id.to_string(),
        current_version: outcome.state.current_version,
        next_version_counter: outcome.state.next_version_counter,
        created_at: now_ms(),
    };
    let v = OkrVersion {
        okr_id: okr.id.clone(),
        version: outcome.new_version,
        objective_md: validate_md(str_field(body, "objectiveMd"))?,
        key_results_md: validate_md(str_field(body, "keyResultsMd"))?,
        valid: true,
        author_id: actor.user_id.clone(),
        created_at: now_ms(),
    };
    store.insert_okr(&okr, &v).await?;
    http_json(&okr_json(store, &okr, &v).await?)
}

async fn edit_okr(
    store: &SqlStore,
    cfg: &Config,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    let mut okr = store
        .get_okr(id)
        .await?
        .ok_or(DomainError::NotFound("okr".into()))?;
    let versions = store.list_okr_versions(id).await?;
    let valid: Vec<u64> = versions
        .iter()
        .filter(|v| v.valid)
        .map(|v| v.version)
        .collect();
    let outcome = version_state(okr.current_version, okr.next_version_counter, &valid).edit();
    okr.current_version = outcome.state.current_version;
    okr.next_version_counter = outcome.state.next_version_counter;
    let v = OkrVersion {
        okr_id: okr.id.clone(),
        version: outcome.new_version,
        objective_md: validate_md(str_field(body, "objectiveMd"))?,
        key_results_md: validate_md(str_field(body, "keyResultsMd"))?,
        valid: true,
        author_id: actor.user_id.clone(),
        created_at: now_ms(),
    };
    store.put_okr_version(&okr, &v).await?;
    // New version "un-does" and notifies assignees (§5.4, §8).
    let assignees = store.list_assignees(&okr.id).await?;
    notify(
        store,
        cfg,
        &assignees,
        NotificationKind::OkrChanged,
        json!({ "humanRef": okr.human_ref }),
    )
    .await
    .ok();
    http_json(&okr_json(store, &okr, &v).await?)
}

async fn okr_versions(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    require_actor(store, req).await?;
    let versions = store.list_okr_versions(id).await?;
    http_json(
        &versions
            .iter()
            .map(|v| json!({
                "version": v.version, "objectiveMd": v.objective_md, "keyResultsMd": v.key_results_md,
                "valid": v.valid, "authorId": v.author_id, "createdAt": v.created_at
            }))
            .collect::<Vec<_>>(),
    )
}

async fn revert_okr(
    store: &SqlStore,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    let mut okr = store
        .get_okr(id)
        .await?
        .ok_or(DomainError::NotFound("okr".into()))?;
    let target = body.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
    let versions = store.list_okr_versions(id).await?;
    let valid: Vec<u64> = versions
        .iter()
        .filter(|v| v.valid)
        .map(|v| v.version)
        .collect();
    let outcome =
        version_state(okr.current_version, okr.next_version_counter, &valid).revert_to(target)?;
    okr.current_version = outcome.state.current_version;
    store.revert_okr(&okr, &outcome.burned).await?;
    http_json(
        &json!({ "ok": true, "currentVersion": okr.current_version, "burned": outcome.burned }),
    )
}

async fn delete_okr(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    store.delete_okr(id).await?;
    http_json(&json!({ "ok": true }))
}

async fn set_assignees(
    store: &SqlStore,
    cfg: &Config,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    require(&actor, Capability::ManageOkrs)?;
    let okr = store
        .get_okr(id)
        .await?
        .ok_or(DomainError::NotFound("okr".into()))?;
    let user_ids: Vec<String> = body
        .get("assignees")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let before = store.list_assignees(id).await?;
    store.set_assignees(id, &user_ids).await?;
    // Notify newly added assignees (§8).
    let added: Vec<String> = user_ids
        .iter()
        .filter(|u| !before.contains(u))
        .cloned()
        .collect();
    notify(
        store,
        cfg,
        &added,
        NotificationKind::OkrAssigned,
        json!({ "humanRef": okr.human_ref }),
    )
    .await
    .ok();
    http_json(&json!({ "ok": true, "assignees": user_ids }))
}

async fn set_done(
    store: &SqlStore,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let okr = store
        .get_okr(id)
        .await?
        .ok_or(DomainError::NotFound("okr".into()))?;
    let assignees = store.list_assignees(id).await?;
    require(&actor, Capability::ContributeToOkr { assignees })?;
    let done = body.get("done").and_then(|v| v.as_bool()).unwrap_or(false);
    let record = OkrDone {
        okr_id: id.to_string(),
        version: okr.current_version,
        done,
        set_by: actor.user_id.clone(),
        set_at: now_ms(),
    };
    store.set_done(&record).await?;
    http_json(&json!({ "ok": true, "done": done, "version": okr.current_version }))
}

// ---------------------------------------------------------------------------
// Updates
// ---------------------------------------------------------------------------

fn update_json(u: &Update, current_version: u64, valid: bool) -> Value {
    json!({
        "id": u.id, "okrId": u.okr_id, "version": u.version,
        "authorId": u.author_id, "bodyMd": u.body_md, "bodyHtml": markdown::render(&u.body_md),
        "createdAt": u.created_at, "editedAt": u.edited_at,
        "fromPreviousVersion": u.version != current_version,
        "versionValid": valid,
    })
}

async fn list_updates(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    require_actor(store, req).await?;
    let okr = store
        .get_okr(id)
        .await?
        .ok_or(DomainError::NotFound("okr".into()))?;
    let versions = store.list_okr_versions(id).await?;
    let valid: std::collections::HashSet<u64> = versions
        .iter()
        .filter(|v| v.valid)
        .map(|v| v.version)
        .collect();
    let url = req
        .url()
        .map_err(|e| DomainError::Internal(e.to_string()))?;
    let q: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();

    let mut updates = store.list_updates(id).await?;
    if q.get("sort").map(|s| s == "desc").unwrap_or(false) {
        updates.reverse();
    }
    let out: Vec<Value> = updates
        .iter()
        .filter(
            |u| match q.get("version").and_then(|v| v.parse::<u64>().ok()) {
                Some(ver) => u.version == ver,
                None => true,
            },
        )
        .filter(|u| match q.get("valid").map(|s| s == "true") {
            Some(want) => valid.contains(&u.version) == want,
            None => true,
        })
        .map(|u| update_json(u, okr.current_version, valid.contains(&u.version)))
        .collect();
    http_json(&out)
}

async fn post_update(
    store: &SqlStore,
    cfg: &Config,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let okr = store
        .get_okr(id)
        .await?
        .ok_or(DomainError::NotFound("okr".into()))?;
    let assignees = store.list_assignees(id).await?;
    require(&actor, Capability::ContributeToOkr { assignees })?;
    let body_md = validate_md(str_field(body, "bodyMd"))?;
    if body_md.trim().is_empty() {
        return Err(DomainError::Invalid("update body must not be empty".into()));
    }
    let update = Update {
        id: ids::new_uuid(),
        okr_id: id.to_string(),
        version: okr.current_version,
        author_id: actor.user_id.clone(),
        body_md,
        created_at: now_ms(),
        edited_at: None,
    };
    store.insert_update(&update).await?;
    // Notify all admins of new progress (§8).
    let admins: Vec<String> = store
        .list_admins()
        .await?
        .into_iter()
        .map(|u| u.id)
        .collect();
    notify(
        store,
        cfg,
        &admins,
        NotificationKind::UpdatePosted,
        json!({ "humanRef": okr.human_ref }),
    )
    .await
    .ok();
    http_json(&update_json(&update, okr.current_version, true))
}

async fn edit_update(
    store: &SqlStore,
    req: &Request,
    id: &str,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let mut update = store
        .get_update(id)
        .await?
        .ok_or(DomainError::NotFound("update".into()))?;
    require(
        &actor,
        Capability::ModifyUpdate {
            author_id: update.author_id.clone(),
        },
    )?;
    update.body_md = validate_md(str_field(body, "bodyMd"))?;
    update.edited_at = Some(now_ms());
    store.update_update(&update).await?;
    http_json(&json!({ "ok": true }))
}

async fn delete_update(store: &SqlStore, req: &Request, id: &str) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let update = store
        .get_update(id)
        .await?
        .ok_or(DomainError::NotFound("update".into()))?;
    require(
        &actor,
        Capability::ModifyUpdate {
            author_id: update.author_id.clone(),
        },
    )?;
    store.delete_update(id).await?;
    http_json(&json!({ "ok": true }))
}

// ---------------------------------------------------------------------------
// Notifications / push
// ---------------------------------------------------------------------------

async fn list_notifications(store: &SqlStore, req: &Request) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let ns = store.list_notifications(&actor.user_id).await?;
    http_json(
        &ns.iter()
            .map(|n| {
                json!({
                    "id": n.id, "kind": n.kind, "payload": n.payload,
                    "createdAt": n.created_at, "readAt": n.read_at
                })
            })
            .collect::<Vec<_>>(),
    )
}

async fn read_notifications(
    store: &SqlStore,
    req: &Request,
    body: &Value,
) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let ids: Vec<String> = body
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    store.mark_notifications_read(&actor.user_id, &ids).await?;
    http_json(&json!({ "ok": true }))
}

async fn push_subscribe(store: &SqlStore, req: &Request, body: &Value) -> DomainResult<Response> {
    let actor = require_actor(store, req).await?;
    let sub = PushSubscription {
        id: ids::new_uuid(),
        user_id: actor.user_id.clone(),
        endpoint: str_field(body, "endpoint").to_string(),
        p256dh: str_field(body, "p256dh").to_string(),
        auth: str_field(body, "auth").to_string(),
        created_at: now_ms(),
    };
    if sub.endpoint.is_empty() {
        return Err(DomainError::Invalid("missing endpoint".into()));
    }
    store.insert_push_subscription(&sub).await?;
    http_json(&json!({ "ok": true }))
}

async fn push_unsubscribe(store: &SqlStore, req: &Request, body: &Value) -> DomainResult<Response> {
    require_actor(store, req).await?;
    store
        .delete_push_subscription(str_field(body, "endpoint"))
        .await?;
    http_json(&json!({ "ok": true }))
}
