//! Persisted entities (spec §4). Field names mirror the SQLite columns in
//! `migrations/`. Times are epoch-milliseconds UTC (`i64`).

use serde::{Deserialize, Serialize};

pub type Millis = i64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserStatus {
    Active,
    Deleted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub name: String,
    /// Auto-generated, unique, immutable (§4.1, §6.1).
    pub short_name: String,
    /// Stable per-user random WebAuthn handle (hex), §6.1.
    pub webauthn_handle: String,
    pub is_admin: bool,
    pub status: UserStatus,
    pub created_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub user_id: String,
    /// Base64url WebAuthn credential id.
    pub webauthn_credential_id: String,
    /// COSE public key bytes (base64url).
    pub public_key: String,
    pub sign_count: u32,
    pub aaguid: String,
    pub transports: Vec<String>,
    pub created_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegCode {
    /// Canonical (ungrouped) code string; stored only as a hash in practice but
    /// modelled here as the value the DO holds.
    pub code: String,
    pub user_id: String,
    pub created_at: Millis,
    pub expires_at: Millis,
    pub used_at: Option<Millis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Session {
    pub id: String,
    pub user_id: String,
    pub created_at: Millis,
    pub expires_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Group {
    pub id: String,
    pub human_ref: String,
    pub current_version: u64,
    pub next_version_counter: u64,
    pub created_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupVersion {
    pub group_id: String,
    pub version: u64,
    pub name: String,
    pub description_md: String,
    pub valid: bool,
    pub author_id: String,
    pub created_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Okr {
    pub id: String,
    pub human_ref: String,
    pub group_id: String,
    pub current_version: u64,
    pub next_version_counter: u64,
    pub created_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkrVersion {
    pub okr_id: String,
    pub version: u64,
    pub objective_md: String,
    pub key_results_md: String,
    pub valid: bool,
    pub author_id: String,
    pub created_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OkrDone {
    pub okr_id: String,
    pub version: u64,
    pub done: bool,
    pub set_by: String,
    pub set_at: Millis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Update {
    pub id: String,
    pub okr_id: String,
    /// OKR version current when the update was posted (§5.5).
    pub version: u64,
    pub author_id: String,
    pub body_md: String,
    pub created_at: Millis,
    pub edited_at: Option<Millis>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NotificationKind {
    OkrAssigned,
    OkrChanged,
    UpdatePosted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Notification {
    pub id: String,
    pub user_id: String,
    pub kind: NotificationKind,
    /// Minimal JSON payload (human ref + event type), §8 payload privacy.
    pub payload: serde_json::Value,
    pub created_at: Millis,
    pub read_at: Option<Millis>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PushSubscription {
    pub id: String,
    pub user_id: String,
    pub endpoint: String,
    pub p256dh: String,
    pub auth: String,
    pub created_at: Millis,
}

/// The authenticated principal derived from a validated session (§7, §11).
/// The worker constructs this from server-side state only — never from
/// client-supplied claims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub user_id: String,
    pub is_admin: bool,
}
