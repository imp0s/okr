# Threat model

Scope: a single-org OKR tracker (< 100 users) on one Cloudflare Worker + one
`Org` Durable Object, GitHub-driven CI/CD. Maps controls to the OWASP Top 10
(spec §11, §13).

## Assets
- OKR/group content and progress updates (low–moderate sensitivity).
- User identities and admin privilege.
- WebAuthn credentials (public keys only — no secret key material is held).
- Secrets: `SETUP_SECRET`, `VAPID_PRIVATE_KEY`, `CF_API_TOKEN`.

## Trust boundaries
- **Client ↔ Worker:** the network edge. All input is untrusted.
- **Worker ↔ Org DO:** internal; the DO is the only writer and the single
  authority for identity, versioning and session validity.
- **GitHub ↔ Cloudflare:** CI holds deploy credentials; least-privilege token.

## Principal/identity
Identity comes **only** from a server-validated session (§11 trust boundary).
The `Actor` (`user_id`, `is_admin`) is built from DO state on every request;
client-sent role flags are never trusted. Every API request re-validates the
session against the DO; deleting a user deletes their sessions in the same
transaction, so existing sessions die on their next request (§6.4).

## OWASP Top 10 (2021) mapping

| Risk | Mitigation |
|---|---|
| **A01 Broken Access Control** | Central authorization matrix in `okr-core::authz`, enforced server-side; admin-only writes/revert; contribute/done gated on assignment for everyone incl. admins; update edit/delete restricted to author/admin. Frontend only hides controls. |
| **A02 Cryptographic Failures** | Passkeys only (no passwords). Sessions are 256-bit CSPRNG opaque tokens. Registration codes ≥ 128-bit, single-use, 24h expiry, compared in constant time (`subtle`). HTTPS-only; HSTS preload. WebAuthn signatures verified with `p256` (ES256). |
| **A03 Injection** | All SQL uses parameterised `?` bindings (no string interpolation of input). Markdown rendered with raw-HTML disabled and link-scheme allow-listing → no stored XSS. No `eval`; CSP forbids inline script. |
| **A04 Insecure Design** | Single serialising DO removes cross-key races; monotonic version counters; atomic ref/short-name uniqueness; fail-closed defaults; documented no-admin recovery. |
| **A05 Security Misconfiguration** | Strict headers on every response: CSP (`default-src 'self'`, `wasm-unsafe-eval` only, `frame-ancestors 'none'`, `object-src 'none'`, `base-uri 'none'`), HSTS, `X-Content-Type-Options`, `Referrer-Policy: no-referrer`, `Permissions-Policy`, `X-Frame-Options: DENY`, COOP. No secrets in `wrangler.toml`. |
| **A06 Vulnerable Components** | Exact-pinned dependencies (no `^`/`~`); `cargo deny` (advisories + licenses) and dependency-review in CI; minimal dependency surface; external JS interop is first-party only. |
| **A07 Identification & Auth Failures** | Discoverable WebAuthn with userVerification; sign-count clone detection; immediate session invalidation; bootstrap path closes after first user; per-IP/per-account rate limiting on auth/registration/code endpoints (DO-backed). |
| **A08 Software & Data Integrity** | CI builds from source; versioned deployments with re-promote rollback; SRI required for any CDN asset (none used — assets are vendored/first-party). |
| **A09 Logging & Monitoring Failures** | Structured Workers logs (`[observability]`); internal errors logged server-side without leaking detail to clients; no PII beyond user IDs; no secret material logged. |
| **A10 SSRF** | The Worker makes only one class of outbound request — Web Push to the subscription's own endpoint origin (VAPID-signed, no user-controlled fan-out). No URL-fetching features. |

## CSRF (§9)
State-changing requests require a same-site signal: `Sec-Fetch-Site:
same-origin|none`, or an `Origin` exactly matching `RP_ORIGIN`. Combined with
`SameSite=Strict; HttpOnly; Secure` cookies. Requests with neither header fail
closed.

## Abuse / DoS
Auth, registration and code endpoints are throttled per window via DO-backed
counters. Request bodies are size-capped; Markdown length-capped. The single DO
naturally serialises and bounds write throughput for a small group.

## Residual risks / assumptions
- **WebAuthn algorithm coverage:** the in-house verifier supports **ES256
  (P-256)** only (spec §6.1 fallback). This covers all mainstream platform and
  roaming authenticators; RS256/EdDSA-only authenticators are unsupported. If
  `webauthn-rs` is later confirmed wasm-clean, swap it in for broader coverage.
- **Web Push payloads:** tickle-only (no encrypted body) — content is fetched
  in-app after click (§8 payload privacy), so no `aes128gcm` payload
  encryption is implemented.
- **Rate limiting** is best-effort per-bucket; it is not a substitute for
  Cloudflare's network-layer DoS protections (relied upon at the edge).
- **No-admin lockout** is recoverable only by a data-wiping redeploy (by
  design, §7 Q10d) — see `RUNBOOK.md`.
- Single org per deployment (v1); the `Storage` trait keeps D1/multi-tenant
  open.
