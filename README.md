# OKR Tracker

A small, self-contained **OKR (Objectives & Key Results) tracker** for a small
group (< 100 users), running as a single **Cloudflare Worker (Rust → WASM)**
backed by one **Durable Object (SQLite)**, with a **Leptos** PWA frontend.
Passkey-only auth (WebAuthn), Markdown progress updates, full version history
with admin revert, in-app + Web Push notifications. Built, tested and deployed
entirely through CI/CD.

## Architecture (spec §3)

```
crates/
├─ core/      # runtime-agnostic domain logic: versioning, revert, refs,
│             # authorization, code validation, Markdown sanitisation.
│             # Pure Rust, fully unit-tested. Persistence via a Storage trait.
├─ worker/    # Cloudflare Worker entry + Org Durable Object.
│             # Implements Storage over DO SQLite; full /api/v1 surface;
│             # sessions, security headers, CSRF, rate limiting, WebAuthn, push.
└─ frontend/  # Leptos CSR WASM SPA (PWA: manifest, sw.js, icon, styles).
migrations/   # DO SQLite schema
.github/workflows/  # CI + preview deploy/teardown + production deploy
docs/         # SECRETS.md, RUNBOOK.md, THREAT-MODEL.md
```

- **One Durable Object** ("org") is the single source of truth; all writes go
  through it so version counters, unique human refs and session invalidation are
  strongly consistent and transactional (spec §3.3).
- **`core` has no Cloudflare deps** — a future D1/container build is a thin
  adapter, not a rewrite (spec §3.2).

## Key behaviours

- **Auth (§6):** passkeys only. Discoverable (usernameless) login. First admin
  bootstrapped with `SETUP_SECRET`; further users via single-use, 24h
  registration codes shown in the admin UI (never emailed).
- **Versioning (§5):** groups and OKRs are versioned; admin **revert** burns
  later versions (numbers permanently consumed, counter never rewinds). Done is
  per-version; updates keep the version stamp they were posted under.
- **Authorization (§7):** read open to all; create/edit/delete/revert/assign are
  admin-only; posting updates / toggling done is gated on assignment for
  everyone (admins included). Enforced server-side in `core`.
- **Security (§11):** strict CSP and security headers, opaque server-validated
  sessions with immediate invalidation, SameSite+Origin CSRF checks,
  parameterised SQL, sanitised Markdown (raw HTML disabled, link-scheme
  allow-list), constant-time code comparison, DO-backed rate limiting, exact
  dependency pins + `cargo deny`. See `docs/THREAT-MODEL.md`.

## Develop

```bash
# Native unit tests (the domain core — the testable centrepiece, spec §15):
cargo test -p okr-core

# Lint exactly as CI does:
cargo fmt --all --check
cargo clippy -p okr-core --all-targets
cargo clippy -p okr-worker -p okr-frontend --target wasm32-unknown-unknown

# Build the WASM artifacts:
cargo install worker-build trunk --locked
bash scripts/build.sh        # -> build/worker/shim.mjs + dist/

# Run locally end-to-end (serves API + assets):
npx wrangler@4.103.0 dev
```

For local `wrangler dev` provide config in a `.dev.vars` file:
`RP_ID=localhost`, `RP_ORIGIN=http://localhost:8787`, `SETUP_SECRET=...`
(see `docs/SECRETS.md`).

## Deploy & CI/CD (spec §13)

- **Push to `main` → production deploy** (`.github/workflows/deploy.yml`):
  versioned deployment; rollback by re-promoting the previous version.
- **Open/update a PR → isolated preview** (`preview.yml`): its own Worker
  `okr-pr-<n>` with its own empty Durable Object datastore; URL posted as a PR
  comment.
- **Close a PR → preview destroyed** (`preview-teardown.yml`).
- **Every PR → quality gates** (`ci.yml`): fmt, clippy (`-D warnings`), tests,
  WASM builds, bundle-size budget, `cargo deny`, dependency review.

**Secrets & variables — what they are, where to find them, how to add them:**
see [`docs/SECRETS.md`](docs/SECRETS.md). Operations (deploy, rollback, bootstrap,
no-admin recovery): [`docs/RUNBOOK.md`](docs/RUNBOOK.md).

## Status / notes

- `okr-core` is fully unit-tested (35 tests incl. the §5.3 revert worked
  example, done-per-version, authz matrix, code expiry/single-use, Markdown
  sanitisation). `worker` and `frontend` compile to `wasm32-unknown-unknown`.
- WebAuthn verification implements the spec's documented in-house **ES256**
  fallback (§6.1); Web Push is tickle-only (§8 minimal-payload). See
  `docs/THREAT-MODEL.md` → *Residual risks* for the precise coverage envelope.
