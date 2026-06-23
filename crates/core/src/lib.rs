//! `okr-core` — runtime-agnostic OKR domain logic (spec §3.1 component 4).
//!
//! Contains all domain types and business rules: versioning, revert, ref
//! generation, authorization, code validation and Markdown sanitisation. It
//! depends on **no** Cloudflare APIs; persistence is injected via the
//! [`storage::Storage`] trait so the same logic can back a Worker/Durable
//! Object today and a container/D1 build later (§3.2).

pub mod authz;
pub mod code;
pub mod done;
pub mod error;
pub mod ids;
pub mod markdown;
pub mod model;
pub mod storage;
pub mod versioning;

pub use error::{DomainError, DomainResult};
