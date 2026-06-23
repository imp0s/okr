//! Domain error type. Mapped to HTTP status codes by the worker crate.

use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, Serialize)]
#[serde(tag = "error", content = "detail", rename_all = "snake_case")]
pub enum DomainError {
    /// Authentication required / session invalid (HTTP 401).
    #[error("unauthenticated")]
    Unauthenticated,
    /// Authenticated but not permitted (HTTP 403).
    #[error("forbidden")]
    Forbidden,
    /// Entity not found (HTTP 404).
    #[error("not found: {0}")]
    NotFound(String),
    /// Input failed validation at the trust boundary (HTTP 400).
    #[error("invalid input: {0}")]
    Invalid(String),
    /// State conflict, e.g. reverting to a burned/unknown version (HTTP 409).
    #[error("conflict: {0}")]
    Conflict(String),
    /// Registration code expired, used, or unknown (HTTP 400/410).
    #[error("registration code rejected")]
    BadRegistrationCode,
    /// The bootstrap path is closed because the system already has users (HTTP 409).
    #[error("setup already completed")]
    SetupClosed,
    /// Rate limit exceeded (HTTP 429).
    #[error("rate limited")]
    RateLimited,
    /// Unexpected server-side failure, e.g. a storage error (HTTP 500). The
    /// detail is for logs only and must never leak secret material.
    #[error("internal error")]
    Internal(String),
}

pub type DomainResult<T> = Result<T, DomainError>;
