# Secrets and variables

> **Canonical store: GitHub.** Every value below lives in GitHub (Actions
> *secrets* or *variables*). The deploy workflows copy the ones the Worker needs
> into Cloudflare via `wrangler secret put`; Cloudflare only ever holds a
> *copy*. Never commit any of these to the repo, put them in `wrangler.toml`, or
> log them. (Spec §14.)

## Where to add them in GitHub

`Settings → Secrets and variables → Actions` on the repository:

- **Secrets** tab → *New repository secret* (encrypted, never printed in logs).
- **Variables** tab → *New repository variable* (plaintext, fine for non-secret
  config).

The deploy jobs read them as `${{ secrets.NAME }}` / `${{ vars.NAME }}`.

## The table

| Name | Type | Lives in | Copied to CF? | How to generate | How to discover |
|---|---|---|---|---|---|
| `CF_API_TOKEN` | **secret** | GitHub Actions secret | n/a (used by CI to call CF) | Cloudflare dashboard → **My Profile → API Tokens → Create Token → Custom token**. Permissions: *Account → Workers Scripts: Edit*, *Account → Account Settings: Read*, *Account → Workers Tail: Read* (optional). Scope it to the one account. | Shown **once** on creation in the Cloudflare dashboard — copy it straight into GitHub. |
| `CF_ACCOUNT_ID` | variable | GitHub Actions variable | n/a | — | Cloudflare dashboard → **Workers & Pages → Overview** (right sidebar), or it is the hex string in the dashboard URL `dash.cloudflare.com/<ACCOUNT_ID>`. |
| `WORKERS_SUBDOMAIN` | variable | GitHub Actions variable | n/a | — | Cloudflare dashboard → **Workers & Pages → Overview**: your `*.workers.dev` subdomain (the `<sub>` in `<worker>.<sub>.workers.dev`). Used to compute preview URLs / `RP_ID`. |
| `SETUP_SECRET` | **secret** | GitHub → Worker (prod) | yes | `openssl rand -hex 32` | Stored in GitHub; injected to the Worker by the deploy job. **Rotate after the first bootstrap.** |
| `PREVIEW_SETUP_SECRET` | **secret** | GitHub → Worker (previews) | yes (preview) | `openssl rand -hex 32` | Used to bootstrap the first admin on every PR preview (each preview has an empty datastore — spec §6.5). |
| `VAPID_PUBLIC_KEY` | variable | GitHub → Worker (also served to the client) | yes | `npx web-push generate-vapid-keys` (pinned), or a P-256 keypair via `openssl ecparam`. Use the **base64url, uncompressed** public point. | Served by `GET /api/v1/push/vapid-public-key`. |
| `VAPID_PRIVATE_KEY` | **secret** | GitHub → Worker | yes | (the private half of the pair above — base64url of the 32-byte scalar `d`) | Never exposed to the client. |
| `RP_ID` | variable | GitHub → Worker | yes | The serving hostname, e.g. `okr.example.com` **or** `okr-tracker.<WORKERS_SUBDOMAIN>.workers.dev`. No scheme, no path. | Your deployment domain. Previews set this automatically to `okr-pr-<n>.<WORKERS_SUBDOMAIN>.workers.dev`. |
| `RP_ORIGIN` | variable | GitHub → Worker | yes | Full HTTPS origin matching `RP_ID`, e.g. `https://okr.example.com`. | Deployment domain. Previews set this automatically. |

> **Sessions need no signing key** — they are opaque 256-bit random IDs stored
> in the Durable Object (spec §6.4 / §14). If you later want signed cookies as
> defence-in-depth, add `SESSION_SIGNING_KEY` (`openssl rand -hex 32`) and wire
> it the same way.

## Generating the VAPID keypair (copy/paste)

```bash
# Pinned tool; prints a base64url public/private pair.
npx --yes web-push@3.6.7 generate-vapid-keys
# -> Public Key:  <base64url>   => VAPID_PUBLIC_KEY (variable)
# -> Private Key: <base64url>   => VAPID_PRIVATE_KEY (secret)
```

## Minimum set to go live

**Production** (push to `main`): `CF_API_TOKEN`, `CF_ACCOUNT_ID`, `RP_ID`,
`RP_ORIGIN`, `SETUP_SECRET`. Push is optional — set `VAPID_PUBLIC_KEY` +
`VAPID_PRIVATE_KEY` to enable Web Push; if omitted, in-app notifications still
work and push is skipped.

**Previews** (per PR): `CF_API_TOKEN`, `CF_ACCOUNT_ID`, `WORKERS_SUBDOMAIN`,
`PREVIEW_SETUP_SECRET` (+ optional VAPID).

## How the values reach Cloudflare

- Non-secret config (`RP_ID`, `RP_ORIGIN`, `VAPID_PUBLIC_KEY`) is passed to
  `wrangler deploy --var KEY:VALUE` (production) or set via `wrangler secret put`
  (previews, so they persist for the preview's lifetime).
- Secrets (`SETUP_SECRET` / `PREVIEW_SETUP_SECRET`, `VAPID_PRIVATE_KEY`) are
  piped into `wrangler secret put` over stdin so they never appear in a command
  line or log.

The Worker reads them through `crates/worker/src/config.rs`, which accepts a
value bound either as a Cloudflare *var* or *secret*.
