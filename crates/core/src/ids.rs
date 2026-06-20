//! Identifier, human-reference, short-name, registration-code and session-id
//! generation. See spec §4.2 (human refs) and §6 (codes / sessions).
//!
//! All randomness comes from `getrandom`, which is backed by the platform CSPRNG
//! natively and by `crypto.getRandomValues` on `wasm32` (the `js` feature).

use crate::error::{DomainError, DomainResult};

/// Unambiguous base32 alphabet from spec §4.2 — no vowels (avoids accidental
/// words) and no look-alike characters (0/O, 1/I/L, U).
pub const UNAMBIGUOUS_ALPHABET: &[u8] = b"23456789CDFGHJKMNPQRSTVWXZ";

/// Fill `buf` with cryptographically secure random bytes.
pub fn random_bytes(buf: &mut [u8]) {
    getrandom::getrandom(buf).expect("platform CSPRNG must be available");
}

/// A fresh UUIDv4 string (server-generated entity id, §4).
pub fn new_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Encode random bytes into `len` characters of the unambiguous alphabet.
fn encode_unambiguous(len: usize) -> String {
    // Draw one byte per character and reduce modulo the alphabet size. The
    // alphabet has 26 symbols; rejection sampling keeps the distribution
    // uniform (256 is not a multiple of 26).
    let n = UNAMBIGUOUS_ALPHABET.len() as u8; // 26
    let limit = 256u16 - (256u16 % n as u16); // largest multiple of n <= 256
    let mut out = String::with_capacity(len);
    let mut byte = [0u8; 1];
    while out.len() < len {
        random_bytes(&mut byte);
        if (byte[0] as u16) < limit {
            out.push(UNAMBIGUOUS_ALPHABET[(byte[0] % n) as usize] as char);
        }
    }
    out
}

/// Entity kind that owns a human reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    Group,
    Okr,
}

impl RefKind {
    fn prefix(self) -> &'static str {
        match self {
            RefKind::Group => "GRP",
            RefKind::Okr => "OKR",
        }
    }
}

/// Generate one candidate human ref, e.g. `OKR-7H2K` (spec §4.2). Uniqueness is
/// guaranteed by the caller via atomic check-and-insert inside the DO.
pub fn gen_human_ref(kind: RefKind) -> String {
    format!("{}-{}", kind.prefix(), encode_unambiguous(4))
}

/// Generate a short, immutable, pronounceable per-user handle used as the
/// WebAuthn `user.name` (§6.1). Uniqueness enforced by the DO.
pub fn gen_short_name() -> String {
    encode_unambiguous(5)
}

/// Generate a single-use registration code with ≥128 bits of entropy (§6.3),
/// rendered in the unambiguous alphabet and grouped for easy hand-off:
/// `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. 26 symbols ≈ 4.7 bits each × 24 ≈ 112 bits…
/// so we use 28 chars (≈131 bits) grouped in 7 blocks of 4.
pub fn gen_registration_code() -> String {
    let raw = encode_unambiguous(28);
    raw.as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap())
        .collect::<Vec<_>>()
        .join("-")
}

/// Normalise a user-entered registration code for comparison: uppercase, strip
/// spaces and dashes. Returns the canonical (ungrouped) form.
pub fn normalise_code(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Opaque 256-bit session id, hex-encoded (§6.4).
pub fn gen_session_id() -> String {
    let mut buf = [0u8; 32];
    random_bytes(&mut buf);
    hex_encode(&buf)
}

/// Stable per-user random WebAuthn handle (the `user.id`, §6.1), 32 bytes.
pub fn gen_webauthn_user_handle() -> [u8; 32] {
    let mut buf = [0u8; 32];
    random_bytes(&mut buf);
    buf
}

pub fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0f) as usize] as char);
    }
    s
}

/// Validate that a human-supplied display name is acceptable (spec §11 input
/// validation): non-empty after trim, within a length cap, no control chars.
pub fn validate_display_name(name: &str) -> DomainResult<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(DomainError::Invalid("name must not be empty".into()));
    }
    if trimmed.chars().count() > 80 {
        return Err(DomainError::Invalid("name must be ≤ 80 characters".into()));
    }
    if trimmed.chars().any(|c| c.is_control()) {
        return Err(DomainError::Invalid(
            "name must not contain control characters".into(),
        ));
    }
    Ok(trimmed.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn refs_have_expected_shape() {
        let r = gen_human_ref(RefKind::Okr);
        assert!(r.starts_with("OKR-"));
        assert_eq!(r.len(), 4 + 4); // "OKR-" + 4 chars
        let g = gen_human_ref(RefKind::Group);
        assert!(g.starts_with("GRP-"));
    }

    #[test]
    fn refs_only_use_unambiguous_alphabet() {
        for _ in 0..1000 {
            let r = gen_human_ref(RefKind::Okr);
            for c in r["OKR-".len()..].bytes() {
                assert!(UNAMBIGUOUS_ALPHABET.contains(&c), "bad char {c}");
            }
        }
    }

    #[test]
    fn refs_are_practically_unique() {
        // Not a uniqueness guarantee (that is the DO's job) — just a sanity check
        // that the generator has entropy.
        let mut seen = HashSet::new();
        for _ in 0..2000 {
            seen.insert(gen_human_ref(RefKind::Okr));
        }
        assert!(seen.len() > 1900, "too many collisions: {}", seen.len());
    }

    #[test]
    fn registration_code_is_grouped_and_high_entropy() {
        let code = gen_registration_code();
        let blocks: Vec<&str> = code.split('-').collect();
        assert_eq!(blocks.len(), 7);
        for b in &blocks {
            assert_eq!(b.len(), 4);
        }
        // Canonical form has 28 alphabet chars.
        assert_eq!(normalise_code(&code).len(), 28);
    }

    #[test]
    fn normalise_code_is_tolerant() {
        assert_eq!(normalise_code("ab cd-ef "), "ABCDEF");
        assert_eq!(normalise_code("23-45 67"), "234567");
    }

    #[test]
    fn session_id_is_256_bits_hex() {
        let s = gen_session_id();
        assert_eq!(s.len(), 64); // 32 bytes -> 64 hex chars
        assert!(s.bytes().all(|b| b.is_ascii_hexdigit()));
    }

    #[test]
    fn display_name_validation() {
        assert_eq!(validate_display_name("  Marc  ").unwrap(), "Marc");
        assert!(validate_display_name("   ").is_err());
        assert!(validate_display_name(&"x".repeat(81)).is_err());
        assert!(validate_display_name("bad\u{0}name").is_err());
    }

    #[test]
    fn hex_encode_matches_expected() {
        assert_eq!(hex_encode(&[0x00, 0xff, 0x10]), "00ff10");
    }
}
