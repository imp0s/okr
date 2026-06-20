//! Persistence abstraction (spec §3.1, §3.2). The domain core depends on no
//! Cloudflare APIs; the worker injects an implementation backed by the `Org`
//! Durable Object's SQLite store. A future D1 / container build is then a thin
//! adapter rather than a rewrite (§3.2 rationale).
//!
//! The trait uses native `async fn` (static dispatch). The worker holds a
//! concrete `Storage` type, so no boxing / `async-trait` dependency is needed.

use crate::error::DomainResult;
use crate::model::*;

/// All reads and writes the domain needs. Implementations must be transactional
/// at the granularity the versioning / ref-uniqueness rules require (§3.3) —
/// the single `Org` DO naturally serialises calls.
#[allow(async_fn_in_trait)]
pub trait Storage {
    // --- bootstrap / users -------------------------------------------------
    /// Number of users that have ever existed; used to gate the bootstrap path
    /// (§6.2). Must count atomically with `insert_user` inside the DO.
    async fn user_count(&self) -> DomainResult<u64>;
    async fn insert_user(&self, user: &User) -> DomainResult<()>;
    async fn get_user(&self, id: &str) -> DomainResult<Option<User>>;
    async fn get_user_by_handle(&self, handle: &str) -> DomainResult<Option<User>>;
    async fn list_users(&self) -> DomainResult<Vec<User>>;
    async fn update_user(&self, user: &User) -> DomainResult<()>;
    /// Delete a user *and* all their sessions/credentials in one transaction
    /// (§6.4 immediate invalidation).
    async fn delete_user(&self, id: &str) -> DomainResult<()>;
    async fn short_name_exists(&self, short_name: &str) -> DomainResult<bool>;

    // --- credentials -------------------------------------------------------
    async fn insert_credential(&self, cred: &Credential) -> DomainResult<()>;
    async fn get_credential(
        &self,
        webauthn_credential_id: &str,
    ) -> DomainResult<Option<Credential>>;
    async fn list_credentials(&self, user_id: &str) -> DomainResult<Vec<Credential>>;
    async fn update_credential_sign_count(&self, id: &str, sign_count: u32) -> DomainResult<()>;
    async fn delete_credential(&self, id: &str, user_id: &str) -> DomainResult<()>;

    // --- registration codes ------------------------------------------------
    async fn insert_reg_code(&self, code: &RegCode) -> DomainResult<()>;
    async fn get_reg_code(&self, code: &str) -> DomainResult<Option<RegCode>>;
    /// Invalidate any outstanding codes for a user before issuing a fresh one
    /// (§6.3 re-registration).
    async fn invalidate_codes_for_user(&self, user_id: &str) -> DomainResult<()>;
    async fn mark_code_used(&self, code: &str, used_at: Millis) -> DomainResult<()>;

    // --- sessions ----------------------------------------------------------
    async fn insert_session(&self, session: &Session) -> DomainResult<()>;
    async fn get_session(&self, id: &str) -> DomainResult<Option<Session>>;
    async fn delete_session(&self, id: &str) -> DomainResult<()>;

    // --- groups ------------------------------------------------------------
    async fn human_ref_exists(&self, human_ref: &str) -> DomainResult<bool>;
    async fn insert_group(&self, group: &Group, v: &GroupVersion) -> DomainResult<()>;
    async fn get_group(&self, id: &str) -> DomainResult<Option<Group>>;
    async fn list_groups(&self) -> DomainResult<Vec<Group>>;
    async fn get_group_version(&self, id: &str, version: u64)
        -> DomainResult<Option<GroupVersion>>;
    async fn list_group_versions(&self, id: &str) -> DomainResult<Vec<GroupVersion>>;
    /// Persist an edit: update the group pointer/counter and add the new version.
    async fn put_group_version(&self, group: &Group, v: &GroupVersion) -> DomainResult<()>;
    /// Persist a revert: update the pointer and burn (`valid=false`) the listed
    /// versions atomically.
    async fn revert_group(&self, group: &Group, burned: &[u64]) -> DomainResult<()>;
    async fn delete_group(&self, id: &str) -> DomainResult<()>;

    // --- okrs --------------------------------------------------------------
    async fn insert_okr(&self, okr: &Okr, v: &OkrVersion) -> DomainResult<()>;
    async fn get_okr(&self, id: &str) -> DomainResult<Option<Okr>>;
    async fn list_okrs(&self) -> DomainResult<Vec<Okr>>;
    async fn get_okr_version(&self, id: &str, version: u64) -> DomainResult<Option<OkrVersion>>;
    async fn list_okr_versions(&self, id: &str) -> DomainResult<Vec<OkrVersion>>;
    async fn put_okr_version(&self, okr: &Okr, v: &OkrVersion) -> DomainResult<()>;
    async fn revert_okr(&self, okr: &Okr, burned: &[u64]) -> DomainResult<()>;
    async fn delete_okr(&self, id: &str) -> DomainResult<()>;

    // --- assignees / done --------------------------------------------------
    async fn set_assignees(&self, okr_id: &str, user_ids: &[String]) -> DomainResult<()>;
    async fn list_assignees(&self, okr_id: &str) -> DomainResult<Vec<String>>;
    async fn list_okrs_for_assignee(&self, user_id: &str) -> DomainResult<Vec<String>>;
    async fn set_done(&self, record: &OkrDone) -> DomainResult<()>;
    async fn list_done(&self, okr_id: &str) -> DomainResult<Vec<OkrDone>>;

    // --- updates -----------------------------------------------------------
    async fn insert_update(&self, update: &Update) -> DomainResult<()>;
    async fn get_update(&self, id: &str) -> DomainResult<Option<Update>>;
    async fn list_updates(&self, okr_id: &str) -> DomainResult<Vec<Update>>;
    async fn update_update(&self, update: &Update) -> DomainResult<()>;
    async fn delete_update(&self, id: &str) -> DomainResult<()>;

    // --- notifications / push ---------------------------------------------
    async fn insert_notification(&self, n: &Notification) -> DomainResult<()>;
    async fn list_notifications(&self, user_id: &str) -> DomainResult<Vec<Notification>>;
    async fn mark_notifications_read(&self, user_id: &str, ids: &[String]) -> DomainResult<()>;
    async fn list_admins(&self) -> DomainResult<Vec<User>>;
    async fn insert_push_subscription(&self, sub: &PushSubscription) -> DomainResult<()>;
    async fn list_push_subscriptions(&self, user_id: &str) -> DomainResult<Vec<PushSubscription>>;
    async fn delete_push_subscription(&self, endpoint: &str) -> DomainResult<()>;

    // --- rate limiting (§11) ----------------------------------------------
    /// Record a hit for `bucket` and return the count within the current
    /// window. Implemented over DO storage so it is consistent.
    async fn rate_limit_hit(&self, bucket: &str, window_ms: i64, now: Millis) -> DomainResult<u32>;
}
