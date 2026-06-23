//! Registration-code and setup-secret verification (spec §6.2, §6.3, §11).
//!
//! Comparisons are constant-time (`subtle`) to avoid leaking match position via
//! timing. Codes are single-use and expire 24h after creation.

use crate::error::{DomainError, DomainResult};
use crate::ids::normalise_code;
use crate::model::{Millis, RegCode};
use subtle::ConstantTimeEq;

/// Registration codes expire 24h after creation (§6.3).
pub const REG_CODE_TTL_MS: Millis = 24 * 60 * 60 * 1000;

/// Sessions live one week (§6.4).
pub const SESSION_TTL_MS: Millis = 7 * 24 * 60 * 60 * 1000;

/// Constant-time string equality.
pub fn ct_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    // Length is not secret here, but short-circuiting on length still avoids an
    // index panic; the byte comparison itself is constant-time.
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Verify a candidate setup secret against the configured value (§6.2).
pub fn verify_setup_secret(provided: &str, expected: &str) -> DomainResult<()> {
    if expected.is_empty() {
        // Misconfiguration: never accept an empty expected secret.
        return Err(DomainError::Forbidden);
    }
    if ct_eq(provided, expected) {
        Ok(())
    } else {
        Err(DomainError::Forbidden)
    }
}

/// Validate a user-entered registration code against a stored `RegCode`
/// (§6.3). Checks, in order: code match (constant-time), single-use, expiry.
/// `now` is epoch-ms.
pub fn validate_reg_code(stored: &RegCode, entered: &str, now: Millis) -> DomainResult<()> {
    let candidate = normalise_code(entered);
    if !ct_eq(&candidate, &stored.code) {
        return Err(DomainError::BadRegistrationCode);
    }
    if stored.used_at.is_some() {
        return Err(DomainError::BadRegistrationCode);
    }
    if now >= stored.expires_at {
        return Err(DomainError::BadRegistrationCode);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(now: Millis) -> RegCode {
        RegCode {
            code: "ABCD2345".into(),
            user_id: "u1".into(),
            created_at: now,
            expires_at: now + REG_CODE_TTL_MS,
            used_at: None,
        }
    }

    #[test]
    fn ct_eq_basic() {
        assert!(ct_eq("hello", "hello"));
        assert!(!ct_eq("hello", "hellp"));
        assert!(!ct_eq("hello", "hell"));
    }

    #[test]
    fn valid_code_accepted_and_tolerant_of_formatting() {
        let now = 1_000_000;
        let c = code(now);
        assert!(validate_reg_code(&c, "abcd-2345", now).is_ok());
        assert!(validate_reg_code(&c, "ABCD 2345", now).is_ok());
    }

    #[test]
    fn wrong_code_rejected() {
        let now = 1_000_000;
        assert!(matches!(
            validate_reg_code(&code(now), "WRONG999", now),
            Err(DomainError::BadRegistrationCode)
        ));
    }

    #[test]
    fn used_code_rejected() {
        let now = 1_000_000;
        let mut c = code(now);
        c.used_at = Some(now);
        assert!(validate_reg_code(&c, "ABCD2345", now).is_err());
    }

    #[test]
    fn expired_code_rejected() {
        let now = 1_000_000;
        let c = code(now);
        assert!(validate_reg_code(&c, "ABCD2345", now + REG_CODE_TTL_MS).is_err());
        assert!(validate_reg_code(&c, "ABCD2345", now + REG_CODE_TTL_MS + 1).is_err());
    }

    #[test]
    fn setup_secret_checks() {
        assert!(verify_setup_secret("s3cr3t", "s3cr3t").is_ok());
        assert!(verify_setup_secret("nope", "s3cr3t").is_err());
        assert!(verify_setup_secret("", "").is_err()); // empty expected never accepted
    }
}
