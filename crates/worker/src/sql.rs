//! `SqlStore` — concrete [`okr_core::storage::Storage`] over the Org Durable
//! Object's SQLite backend (spec §3.1/§3.2). All calls are naturally serialised
//! by the single DO, giving the transactional guarantees the versioning and
//! ref-uniqueness rules require (§3.3).
//!
//! `SqlStorage::exec` is synchronous in the DO, so the async trait methods here
//! simply wrap synchronous calls.

use okr_core::model::*;
use okr_core::storage::Storage;
use okr_core::{DomainError, DomainResult};
use serde::Deserialize;
use worker::{SqlStorage, SqlStorageValue};

pub struct SqlStore {
    sql: SqlStorage,
}

fn db<E: std::fmt::Display>(e: E) -> DomainError {
    DomainError::Internal(format!("db: {e}"))
}

impl SqlStore {
    pub fn new(sql: SqlStorage) -> Self {
        Self { sql }
    }

    /// Apply the embedded schema. Idempotent (`CREATE TABLE IF NOT EXISTS`).
    pub fn ensure_schema(&self) -> DomainResult<()> {
        for stmt in include_str!("../../../migrations/0001_init.sql").split(';') {
            let s = stmt.trim();
            if !s.is_empty() {
                self.sql.exec(s, None).map_err(db)?;
            }
        }
        Ok(())
    }

    fn rows<T: serde::de::DeserializeOwned>(
        &self,
        q: &str,
        b: Vec<SqlStorageValue>,
    ) -> DomainResult<Vec<T>> {
        self.sql.exec(q, b).map_err(db)?.to_array::<T>().map_err(db)
    }

    fn run(&self, q: &str, b: Vec<SqlStorageValue>) -> DomainResult<()> {
        self.sql.exec(q, b).map_err(db)?;
        Ok(())
    }

    // ---- challenge storage (used by webauthn.rs; not part of the trait) ----
    pub fn put_challenge(
        &self,
        id: &str,
        kind: &str,
        challenge: &str,
        user_id: Option<&str>,
        data: Option<&str>,
        expires_at: i64,
    ) -> DomainResult<()> {
        self.run(
            "INSERT INTO challenges (id, kind, challenge, user_id, data, expires_at) VALUES (?,?,?,?,?,?)",
            vec![
                id.into(),
                kind.into(),
                challenge.into(),
                user_id.unwrap_or("").into(),
                data.unwrap_or("").into(),
                expires_at.into(),
            ],
        )
    }

    pub fn take_challenge(&self, id: &str, now: i64) -> DomainResult<Option<ChallengeRow>> {
        let found: Vec<ChallengeRow> = self.rows(
            "SELECT id, kind, challenge, user_id, data, expires_at FROM challenges WHERE id = ?",
            vec![id.into()],
        )?;
        self.run("DELETE FROM challenges WHERE id = ?", vec![id.into()])?;
        Ok(found
            .into_iter()
            .find(|c| c.expires_at > now && !c.id.is_empty()))
    }
}

// --- row mappers (booleans/JSON need conversion from raw columns) ---

#[derive(Deserialize)]
struct UserRow {
    id: String,
    name: String,
    short_name: String,
    webauthn_handle: String,
    is_admin: i64,
    status: String,
    created_at: i64,
}
impl From<UserRow> for User {
    fn from(r: UserRow) -> Self {
        User {
            id: r.id,
            name: r.name,
            short_name: r.short_name,
            webauthn_handle: r.webauthn_handle,
            is_admin: r.is_admin != 0,
            status: if r.status == "deleted" {
                UserStatus::Deleted
            } else {
                UserStatus::Active
            },
            created_at: r.created_at,
        }
    }
}

#[derive(Deserialize)]
struct CredRow {
    id: String,
    user_id: String,
    webauthn_credential_id: String,
    public_key: String,
    sign_count: i64,
    aaguid: String,
    transports: String,
    created_at: i64,
}
impl From<CredRow> for Credential {
    fn from(r: CredRow) -> Self {
        Credential {
            id: r.id,
            user_id: r.user_id,
            webauthn_credential_id: r.webauthn_credential_id,
            public_key: r.public_key,
            sign_count: r.sign_count as u32,
            aaguid: r.aaguid,
            transports: serde_json::from_str(&r.transports).unwrap_or_default(),
            created_at: r.created_at,
        }
    }
}

#[derive(Deserialize)]
struct GvRow {
    group_id: String,
    version: i64,
    name: String,
    description_md: String,
    valid: i64,
    author_id: String,
    created_at: i64,
}
impl From<GvRow> for GroupVersion {
    fn from(r: GvRow) -> Self {
        GroupVersion {
            group_id: r.group_id,
            version: r.version as u64,
            name: r.name,
            description_md: r.description_md,
            valid: r.valid != 0,
            author_id: r.author_id,
            created_at: r.created_at,
        }
    }
}

#[derive(Deserialize)]
struct OvRow {
    okr_id: String,
    version: i64,
    objective_md: String,
    key_results_md: String,
    valid: i64,
    author_id: String,
    created_at: i64,
}
impl From<OvRow> for OkrVersion {
    fn from(r: OvRow) -> Self {
        OkrVersion {
            okr_id: r.okr_id,
            version: r.version as u64,
            objective_md: r.objective_md,
            key_results_md: r.key_results_md,
            valid: r.valid != 0,
            author_id: r.author_id,
            created_at: r.created_at,
        }
    }
}

#[derive(Deserialize)]
struct OdRow {
    okr_id: String,
    version: i64,
    done: i64,
    set_by: String,
    set_at: i64,
}
impl From<OdRow> for OkrDone {
    fn from(r: OdRow) -> Self {
        OkrDone {
            okr_id: r.okr_id,
            version: r.version as u64,
            done: r.done != 0,
            set_by: r.set_by,
            set_at: r.set_at,
        }
    }
}

#[derive(Deserialize)]
struct NotifRow {
    id: String,
    user_id: String,
    kind: String,
    payload: String,
    created_at: i64,
    read_at: Option<i64>,
}
impl From<NotifRow> for Notification {
    fn from(r: NotifRow) -> Self {
        let kind = match r.kind.as_str() {
            "okr_assigned" => NotificationKind::OkrAssigned,
            "okr_changed" => NotificationKind::OkrChanged,
            _ => NotificationKind::UpdatePosted,
        };
        Notification {
            id: r.id,
            user_id: r.user_id,
            kind,
            payload: serde_json::from_str(&r.payload).unwrap_or(serde_json::Value::Null),
            created_at: r.created_at,
            read_at: r.read_at,
        }
    }
}

#[derive(Deserialize)]
pub struct ChallengeRow {
    pub id: String,
    pub kind: String,
    pub challenge: String,
    pub user_id: String,
    pub data: String,
    pub expires_at: i64,
}

#[derive(Deserialize)]
struct CountRow {
    n: i64,
}
#[derive(Deserialize)]
struct ExistsRow {
    n: i64,
}
#[derive(Deserialize)]
struct HitsRow {
    hits: i64,
}
#[derive(Deserialize)]
struct OkrIdRow {
    okr_id: String,
}
#[derive(Deserialize)]
struct UserIdRow {
    user_id: String,
}

fn nstr(kind: NotificationKind) -> &'static str {
    match kind {
        NotificationKind::OkrAssigned => "okr_assigned",
        NotificationKind::OkrChanged => "okr_changed",
        NotificationKind::UpdatePosted => "update_posted",
    }
}

impl Storage for SqlStore {
    async fn user_count(&self) -> DomainResult<u64> {
        let r: Vec<CountRow> = self.rows("SELECT COUNT(*) AS n FROM users", vec![])?;
        Ok(r.first().map(|x| x.n as u64).unwrap_or(0))
    }

    async fn insert_user(&self, u: &User) -> DomainResult<()> {
        self.run(
            "INSERT INTO users (id, name, short_name, webauthn_handle, is_admin, status, created_at) VALUES (?,?,?,?,?,?,?)",
            vec![
                u.id.as_str().into(),
                u.name.as_str().into(),
                u.short_name.as_str().into(),
                u.webauthn_handle.as_str().into(),
                (u.is_admin as i64).into(),
                "active".into(),
                u.created_at.into(),
            ],
        )
    }

    async fn get_user(&self, id: &str) -> DomainResult<Option<User>> {
        let r: Vec<UserRow> = self.rows("SELECT * FROM users WHERE id = ?", vec![id.into()])?;
        Ok(r.into_iter().next().map(Into::into))
    }

    async fn get_user_by_handle(&self, handle: &str) -> DomainResult<Option<User>> {
        let r: Vec<UserRow> = self.rows(
            "SELECT * FROM users WHERE webauthn_handle = ?",
            vec![handle.into()],
        )?;
        Ok(r.into_iter().next().map(Into::into))
    }

    async fn list_users(&self) -> DomainResult<Vec<User>> {
        let r: Vec<UserRow> = self.rows("SELECT * FROM users ORDER BY created_at", vec![])?;
        Ok(r.into_iter().map(Into::into).collect())
    }

    async fn update_user(&self, u: &User) -> DomainResult<()> {
        self.run(
            "UPDATE users SET name = ?, is_admin = ?, status = ? WHERE id = ?",
            vec![
                u.name.as_str().into(),
                (u.is_admin as i64).into(),
                (if u.status == UserStatus::Deleted {
                    "deleted"
                } else {
                    "active"
                })
                .into(),
                u.id.as_str().into(),
            ],
        )
    }

    async fn delete_user(&self, id: &str) -> DomainResult<()> {
        // FK ON DELETE CASCADE removes sessions/credentials/etc. atomically.
        self.run("DELETE FROM users WHERE id = ?", vec![id.into()])
    }

    async fn short_name_exists(&self, short_name: &str) -> DomainResult<bool> {
        let r: Vec<ExistsRow> = self.rows(
            "SELECT COUNT(*) AS n FROM users WHERE short_name = ?",
            vec![short_name.into()],
        )?;
        Ok(r.first().map(|x| x.n > 0).unwrap_or(false))
    }

    async fn insert_credential(&self, c: &Credential) -> DomainResult<()> {
        self.run(
            "INSERT INTO credentials (id, user_id, webauthn_credential_id, public_key, sign_count, aaguid, transports, created_at) VALUES (?,?,?,?,?,?,?,?)",
            vec![
                c.id.as_str().into(),
                c.user_id.as_str().into(),
                c.webauthn_credential_id.as_str().into(),
                c.public_key.as_str().into(),
                (c.sign_count as i64).into(),
                c.aaguid.as_str().into(),
                serde_json::to_string(&c.transports).unwrap_or_else(|_| "[]".into()).into(),
                c.created_at.into(),
            ],
        )
    }

    async fn get_credential(&self, cred_id: &str) -> DomainResult<Option<Credential>> {
        let r: Vec<CredRow> = self.rows(
            "SELECT * FROM credentials WHERE webauthn_credential_id = ?",
            vec![cred_id.into()],
        )?;
        Ok(r.into_iter().next().map(Into::into))
    }

    async fn list_credentials(&self, user_id: &str) -> DomainResult<Vec<Credential>> {
        let r: Vec<CredRow> = self.rows(
            "SELECT * FROM credentials WHERE user_id = ?",
            vec![user_id.into()],
        )?;
        Ok(r.into_iter().map(Into::into).collect())
    }

    async fn update_credential_sign_count(&self, id: &str, n: u32) -> DomainResult<()> {
        self.run(
            "UPDATE credentials SET sign_count = ? WHERE id = ?",
            vec![(n as i64).into(), id.into()],
        )
    }

    async fn delete_credential(&self, id: &str, user_id: &str) -> DomainResult<()> {
        self.run(
            "DELETE FROM credentials WHERE id = ? AND user_id = ?",
            vec![id.into(), user_id.into()],
        )
    }

    async fn insert_reg_code(&self, c: &RegCode) -> DomainResult<()> {
        self.run(
            "INSERT INTO reg_codes (code, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            vec![
                c.code.as_str().into(),
                c.user_id.as_str().into(),
                c.created_at.into(),
                c.expires_at.into(),
            ],
        )
    }

    async fn get_reg_code(&self, code: &str) -> DomainResult<Option<RegCode>> {
        #[derive(Deserialize)]
        struct R {
            code: String,
            user_id: String,
            created_at: i64,
            expires_at: i64,
            used_at: Option<i64>,
        }
        let r: Vec<R> = self.rows("SELECT * FROM reg_codes WHERE code = ?", vec![code.into()])?;
        Ok(r.into_iter().next().map(|r| RegCode {
            code: r.code,
            user_id: r.user_id,
            created_at: r.created_at,
            expires_at: r.expires_at,
            used_at: r.used_at,
        }))
    }

    async fn invalidate_codes_for_user(&self, user_id: &str) -> DomainResult<()> {
        self.run(
            "DELETE FROM reg_codes WHERE user_id = ?",
            vec![user_id.into()],
        )
    }

    async fn mark_code_used(&self, code: &str, used_at: Millis) -> DomainResult<()> {
        self.run(
            "UPDATE reg_codes SET used_at = ? WHERE code = ?",
            vec![used_at.into(), code.into()],
        )
    }

    async fn insert_session(&self, s: &Session) -> DomainResult<()> {
        self.run(
            "INSERT INTO sessions (id, user_id, created_at, expires_at) VALUES (?,?,?,?)",
            vec![
                s.id.as_str().into(),
                s.user_id.as_str().into(),
                s.created_at.into(),
                s.expires_at.into(),
            ],
        )
    }

    async fn get_session(&self, id: &str) -> DomainResult<Option<Session>> {
        let r: Vec<Session> = self.rows("SELECT * FROM sessions WHERE id = ?", vec![id.into()])?;
        Ok(r.into_iter().next())
    }

    async fn delete_session(&self, id: &str) -> DomainResult<()> {
        self.run("DELETE FROM sessions WHERE id = ?", vec![id.into()])
    }

    async fn human_ref_exists(&self, human_ref: &str) -> DomainResult<bool> {
        let r: Vec<ExistsRow> = self.rows(
            "SELECT (SELECT COUNT(*) FROM groups WHERE human_ref = ?1) + (SELECT COUNT(*) FROM okrs WHERE human_ref = ?1) AS n",
            vec![human_ref.into()],
        )?;
        Ok(r.first().map(|x| x.n > 0).unwrap_or(false))
    }

    async fn insert_group(&self, g: &Group, v: &GroupVersion) -> DomainResult<()> {
        self.run(
            "INSERT INTO groups (id, human_ref, current_version, next_version_counter, created_at) VALUES (?,?,?,?,?)",
            vec![
                g.id.as_str().into(),
                g.human_ref.as_str().into(),
                (g.current_version as i64).into(),
                (g.next_version_counter as i64).into(),
                g.created_at.into(),
            ],
        )?;
        self.insert_group_version_row(v)
    }

    async fn get_group(&self, id: &str) -> DomainResult<Option<Group>> {
        let r: Vec<Group> = self.rows("SELECT * FROM groups WHERE id = ?", vec![id.into()])?;
        Ok(r.into_iter().next())
    }

    async fn list_groups(&self) -> DomainResult<Vec<Group>> {
        self.rows("SELECT * FROM groups ORDER BY created_at", vec![])
    }

    async fn get_group_version(
        &self,
        id: &str,
        version: u64,
    ) -> DomainResult<Option<GroupVersion>> {
        let r: Vec<GvRow> = self.rows(
            "SELECT * FROM group_versions WHERE group_id = ? AND version = ?",
            vec![id.into(), (version as i64).into()],
        )?;
        Ok(r.into_iter().next().map(Into::into))
    }

    async fn list_group_versions(&self, id: &str) -> DomainResult<Vec<GroupVersion>> {
        let r: Vec<GvRow> = self.rows(
            "SELECT * FROM group_versions WHERE group_id = ? ORDER BY version",
            vec![id.into()],
        )?;
        Ok(r.into_iter().map(Into::into).collect())
    }

    async fn put_group_version(&self, g: &Group, v: &GroupVersion) -> DomainResult<()> {
        self.run(
            "UPDATE groups SET current_version = ?, next_version_counter = ? WHERE id = ?",
            vec![
                (g.current_version as i64).into(),
                (g.next_version_counter as i64).into(),
                g.id.as_str().into(),
            ],
        )?;
        self.insert_group_version_row(v)
    }

    async fn revert_group(&self, g: &Group, burned: &[u64]) -> DomainResult<()> {
        self.run(
            "UPDATE groups SET current_version = ? WHERE id = ?",
            vec![(g.current_version as i64).into(), g.id.as_str().into()],
        )?;
        for v in burned {
            self.run(
                "UPDATE group_versions SET valid = 0 WHERE group_id = ? AND version = ?",
                vec![g.id.as_str().into(), (*v as i64).into()],
            )?;
        }
        Ok(())
    }

    async fn delete_group(&self, id: &str) -> DomainResult<()> {
        self.run("DELETE FROM groups WHERE id = ?", vec![id.into()])
    }

    async fn insert_okr(&self, o: &Okr, v: &OkrVersion) -> DomainResult<()> {
        self.run(
            "INSERT INTO okrs (id, human_ref, group_id, current_version, next_version_counter, created_at) VALUES (?,?,?,?,?,?)",
            vec![
                o.id.as_str().into(),
                o.human_ref.as_str().into(),
                o.group_id.as_str().into(),
                (o.current_version as i64).into(),
                (o.next_version_counter as i64).into(),
                o.created_at.into(),
            ],
        )?;
        self.insert_okr_version_row(v)
    }

    async fn get_okr(&self, id: &str) -> DomainResult<Option<Okr>> {
        let r: Vec<Okr> = self.rows("SELECT * FROM okrs WHERE id = ?", vec![id.into()])?;
        Ok(r.into_iter().next())
    }

    async fn list_okrs(&self) -> DomainResult<Vec<Okr>> {
        self.rows("SELECT * FROM okrs ORDER BY created_at", vec![])
    }

    async fn get_okr_version(&self, id: &str, version: u64) -> DomainResult<Option<OkrVersion>> {
        let r: Vec<OvRow> = self.rows(
            "SELECT * FROM okr_versions WHERE okr_id = ? AND version = ?",
            vec![id.into(), (version as i64).into()],
        )?;
        Ok(r.into_iter().next().map(Into::into))
    }

    async fn list_okr_versions(&self, id: &str) -> DomainResult<Vec<OkrVersion>> {
        let r: Vec<OvRow> = self.rows(
            "SELECT * FROM okr_versions WHERE okr_id = ? ORDER BY version",
            vec![id.into()],
        )?;
        Ok(r.into_iter().map(Into::into).collect())
    }

    async fn put_okr_version(&self, o: &Okr, v: &OkrVersion) -> DomainResult<()> {
        self.run(
            "UPDATE okrs SET current_version = ?, next_version_counter = ? WHERE id = ?",
            vec![
                (o.current_version as i64).into(),
                (o.next_version_counter as i64).into(),
                o.id.as_str().into(),
            ],
        )?;
        self.insert_okr_version_row(v)
    }

    async fn revert_okr(&self, o: &Okr, burned: &[u64]) -> DomainResult<()> {
        self.run(
            "UPDATE okrs SET current_version = ? WHERE id = ?",
            vec![(o.current_version as i64).into(), o.id.as_str().into()],
        )?;
        for v in burned {
            self.run(
                "UPDATE okr_versions SET valid = 0 WHERE okr_id = ? AND version = ?",
                vec![o.id.as_str().into(), (*v as i64).into()],
            )?;
        }
        Ok(())
    }

    async fn delete_okr(&self, id: &str) -> DomainResult<()> {
        self.run("DELETE FROM okrs WHERE id = ?", vec![id.into()])
    }

    async fn set_assignees(&self, okr_id: &str, user_ids: &[String]) -> DomainResult<()> {
        self.run(
            "DELETE FROM okr_assignees WHERE okr_id = ?",
            vec![okr_id.into()],
        )?;
        for uid in user_ids {
            self.run(
                "INSERT OR IGNORE INTO okr_assignees (okr_id, user_id) VALUES (?,?)",
                vec![okr_id.into(), uid.as_str().into()],
            )?;
        }
        Ok(())
    }

    async fn list_assignees(&self, okr_id: &str) -> DomainResult<Vec<String>> {
        let r: Vec<UserIdRow> = self.rows(
            "SELECT user_id FROM okr_assignees WHERE okr_id = ?",
            vec![okr_id.into()],
        )?;
        Ok(r.into_iter().map(|x| x.user_id).collect())
    }

    async fn list_okrs_for_assignee(&self, user_id: &str) -> DomainResult<Vec<String>> {
        let r: Vec<OkrIdRow> = self.rows(
            "SELECT okr_id FROM okr_assignees WHERE user_id = ?",
            vec![user_id.into()],
        )?;
        Ok(r.into_iter().map(|x| x.okr_id).collect())
    }

    async fn set_done(&self, d: &OkrDone) -> DomainResult<()> {
        self.run(
            "INSERT OR REPLACE INTO okr_done (okr_id, version, done, set_by, set_at) VALUES (?,?,?,?,?)",
            vec![
                d.okr_id.as_str().into(),
                (d.version as i64).into(),
                (d.done as i64).into(),
                d.set_by.as_str().into(),
                d.set_at.into(),
            ],
        )
    }

    async fn list_done(&self, okr_id: &str) -> DomainResult<Vec<OkrDone>> {
        let r: Vec<OdRow> = self.rows(
            "SELECT * FROM okr_done WHERE okr_id = ? ORDER BY set_at",
            vec![okr_id.into()],
        )?;
        Ok(r.into_iter().map(Into::into).collect())
    }

    async fn insert_update(&self, u: &Update) -> DomainResult<()> {
        self.run(
            "INSERT INTO updates (id, okr_id, version, author_id, body_md, created_at) VALUES (?,?,?,?,?,?)",
            vec![
                u.id.as_str().into(),
                u.okr_id.as_str().into(),
                (u.version as i64).into(),
                u.author_id.as_str().into(),
                u.body_md.as_str().into(),
                u.created_at.into(),
            ],
        )
    }

    async fn get_update(&self, id: &str) -> DomainResult<Option<Update>> {
        let r: Vec<Update> = self.rows("SELECT * FROM updates WHERE id = ?", vec![id.into()])?;
        Ok(r.into_iter().next())
    }

    async fn list_updates(&self, okr_id: &str) -> DomainResult<Vec<Update>> {
        self.rows(
            "SELECT * FROM updates WHERE okr_id = ? ORDER BY created_at",
            vec![okr_id.into()],
        )
    }

    async fn update_update(&self, u: &Update) -> DomainResult<()> {
        self.run(
            "UPDATE updates SET body_md = ?, edited_at = ? WHERE id = ?",
            vec![
                u.body_md.as_str().into(),
                u.edited_at.unwrap_or(0).into(),
                u.id.as_str().into(),
            ],
        )
    }

    async fn delete_update(&self, id: &str) -> DomainResult<()> {
        self.run("DELETE FROM updates WHERE id = ?", vec![id.into()])
    }

    async fn insert_notification(&self, n: &Notification) -> DomainResult<()> {
        self.run(
            "INSERT INTO notifications (id, user_id, kind, payload, created_at) VALUES (?,?,?,?,?)",
            vec![
                n.id.as_str().into(),
                n.user_id.as_str().into(),
                nstr(n.kind).into(),
                serde_json::to_string(&n.payload)
                    .unwrap_or_else(|_| "{}".into())
                    .into(),
                n.created_at.into(),
            ],
        )
    }

    async fn list_notifications(&self, user_id: &str) -> DomainResult<Vec<Notification>> {
        let r: Vec<NotifRow> = self.rows(
            "SELECT * FROM notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 200",
            vec![user_id.into()],
        )?;
        Ok(r.into_iter().map(Into::into).collect())
    }

    async fn mark_notifications_read(&self, user_id: &str, ids: &[String]) -> DomainResult<()> {
        let now = crate::now_ms();
        for id in ids {
            self.run(
                "UPDATE notifications SET read_at = ? WHERE id = ? AND user_id = ?",
                vec![now.into(), id.as_str().into(), user_id.into()],
            )?;
        }
        Ok(())
    }

    async fn list_admins(&self) -> DomainResult<Vec<User>> {
        let r: Vec<UserRow> = self.rows(
            "SELECT * FROM users WHERE is_admin = 1 AND status = 'active'",
            vec![],
        )?;
        Ok(r.into_iter().map(Into::into).collect())
    }

    async fn insert_push_subscription(&self, s: &PushSubscription) -> DomainResult<()> {
        self.run(
            "INSERT OR REPLACE INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, created_at) VALUES (?,?,?,?,?,?)",
            vec![
                s.id.as_str().into(),
                s.user_id.as_str().into(),
                s.endpoint.as_str().into(),
                s.p256dh.as_str().into(),
                s.auth.as_str().into(),
                s.created_at.into(),
            ],
        )
    }

    async fn list_push_subscriptions(&self, user_id: &str) -> DomainResult<Vec<PushSubscription>> {
        self.rows(
            "SELECT * FROM push_subscriptions WHERE user_id = ?",
            vec![user_id.into()],
        )
    }

    async fn delete_push_subscription(&self, endpoint: &str) -> DomainResult<()> {
        self.run(
            "DELETE FROM push_subscriptions WHERE endpoint = ?",
            vec![endpoint.into()],
        )
    }

    async fn rate_limit_hit(&self, bucket: &str, window_ms: i64, now: Millis) -> DomainResult<u32> {
        let window_start = now - (now % window_ms.max(1));
        let r: Vec<HitsRow> = self.rows(
            "INSERT INTO rate_limits (bucket, window_start, hits) VALUES (?,?,1) \
             ON CONFLICT(bucket, window_start) DO UPDATE SET hits = hits + 1 RETURNING hits",
            vec![bucket.into(), window_start.into()],
        )?;
        Ok(r.first().map(|x| x.hits as u32).unwrap_or(1))
    }
}

impl SqlStore {
    fn insert_group_version_row(&self, v: &GroupVersion) -> DomainResult<()> {
        self.run(
            "INSERT INTO group_versions (group_id, version, name, description_md, valid, author_id, created_at) VALUES (?,?,?,?,?,?,?)",
            vec![
                v.group_id.as_str().into(),
                (v.version as i64).into(),
                v.name.as_str().into(),
                v.description_md.as_str().into(),
                (v.valid as i64).into(),
                v.author_id.as_str().into(),
                v.created_at.into(),
            ],
        )
    }

    fn insert_okr_version_row(&self, v: &OkrVersion) -> DomainResult<()> {
        self.run(
            "INSERT INTO okr_versions (okr_id, version, objective_md, key_results_md, valid, author_id, created_at) VALUES (?,?,?,?,?,?,?)",
            vec![
                v.okr_id.as_str().into(),
                (v.version as i64).into(),
                v.objective_md.as_str().into(),
                v.key_results_md.as_str().into(),
                (v.valid as i64).into(),
                v.author_id.as_str().into(),
                v.created_at.into(),
            ],
        )
    }
}
