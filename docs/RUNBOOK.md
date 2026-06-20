# Runbook — deploy, rollback, recovery

Operational procedures for the OKR Tracker (spec §16). GitHub is the source of
truth and orchestrator; Cloudflare holds deploy-time copies of secrets only.

## 1. One-time setup

1. Create the Cloudflare API token and gather IDs — see `docs/SECRETS.md`.
2. Add all GitHub secrets/variables (`docs/SECRETS.md` table).
3. Decide the production hostname:
   - **workers.dev:** set `RP_ID = okr-tracker.<WORKERS_SUBDOMAIN>.workers.dev`,
     `RP_ORIGIN = https://<that host>`.
   - **custom domain:** add a route/custom-domain to the `okr-tracker` Worker in
     the Cloudflare dashboard, then set `RP_ID`/`RP_ORIGIN` to that domain.
4. Configure branch protection (§4 below).
5. Push to `main` → the **Deploy Production** workflow builds and deploys.

## 2. First admin (bootstrap)

The first registration on an empty datastore is gated by `SETUP_SECRET`
(spec §6.2). After deploy:

1. Open the app, expand **First-time setup**, paste the `SETUP_SECRET`, register
   a passkey. You become `is_admin = true`.
2. The bootstrap path then closes permanently (guarded inside the DO).
3. **Rotate `SETUP_SECRET`** afterwards (new random value in GitHub; it is only
   needed to re-bootstrap after a wipe).

Thereafter, admins create users in-app; each yields a **registration code**
shown in the admin UI to hand over out-of-band (no email is ever sent, §1.1).

## 3. Deploy & rollback

### Normal deploy
Merging to `main` triggers `.github/workflows/deploy.yml`, which:
1. Ensures Worker secrets are set (`wrangler secret put`, idempotent).
2. Runs `wrangler deploy` with `RP_ID`/`RP_ORIGIN`/`VAPID_PUBLIC_KEY` as bundled
   vars — this uploads a new immutable version and activates it.

### Rollback (spec §16)
Re-promote the previous version:

```bash
wrangler deployments list           # find the prior version id
wrangler rollback [<version-id>]    # re-promote it; --message "reason"
```

Because migrations are additive/backward-compatible (§3.2 below), rolling the
code back is safe against the existing SQLite data.

### Gradual rollout (optional, spec §13.2)
The default deploy is atomic. To roll out gradually (requires a Workers paid
plan), replace the deploy step with versioned promotion:

```bash
# 1. Upload (does not serve traffic yet):
NEW=$(wrangler versions upload \
  --var RP_ID:$RP_ID --var RP_ORIGIN:$RP_ORIGIN --var VAPID_PUBLIC_KEY:$VAPID_PUBLIC_KEY \
  --json | jq -r '.id')
PREV=$(wrangler deployments list --json | jq -r '.[0].versions[0].version_id')

# 2. Serve 10% from the new version, 90% from the previous:
wrangler versions deploy "${NEW}@10" "${PREV}@90" --yes

# 3. After soak (metrics OK), promote to 100%:
wrangler versions deploy "${NEW}@100" --yes
# Bad version? Re-promote the previous one to 100% (instant rollback):
wrangler versions deploy "${PREV}@100" --yes
```

## 4. Branch protection (spec §13.3)

Configure on `main` (`Settings → Branches → Add rule`):
- Protect against deletion and force-push.
- Require pull request review (≥ 1) and "up-to-date branch before merge".
- Require status checks: **CI / quality**, **CI / bundle-size**,
  **CI / supply-chain**, **CI / dependency-review**.
- Linear history (squash or rebase); no direct pushes to `main`.

## 5. PR previews (spec §13.1.2/3)

- Opening/updating a PR (same-repo) deploys an isolated Worker
  `okr-pr-<number>` with its **own** Durable Object namespace and empty
  datastore; the URL is posted as a PR comment. Bootstrap it with
  `PREVIEW_SETUP_SECRET`.
- Closing the PR deletes the preview Worker and its data (`wrangler delete
  --force`).
- Passkeys are origin-bound: production passkeys do not work on previews and
  vice-versa (spec §6.5). This is expected.

## 3.2 Schema migrations

Schema lives in `migrations/0001_init.sql` and is applied idempotently by the DO
on first request (`CREATE TABLE IF NOT EXISTS`). For changes:

- **Additive** (new table/column/index): add a new `migrations/000N_*.sql`,
  apply it idempotently, deploy. Backward-compatible → safe rollback.
- **Destructive** (drop/rename/retype): use **expand → migrate → contract**
  across releases (add new shape; dual-write/backfill; switch reads; later
  remove the old shape). Provide a down-migration where technically possible;
  document where not.

## 6. No-admin recovery (spec §7 Q10d, §16)

There is **no last-admin safeguard** by design — the system tolerates a
no-admin state. If every admin is removed/deleted:

1. There is no in-app path to regain admin.
2. Recovery is by **redeploying to bootstrap state**: wipe the Org DO's data so
   `user_count() == 0`, which re-opens the `SETUP_SECRET` bootstrap path.

To wipe production data (irreversible — **all OKRs/updates are lost**), the
simplest supported method is to delete and recreate the Worker's Durable Object
storage:

```bash
# Deletes the script AND its DO storage, then redeploy fresh:
wrangler delete --name okr-tracker --force
git commit --allow-empty -m "redeploy" && git push   # triggers a clean deploy
```

Then bootstrap a new first admin (§2). **Document/communicate the data loss
before doing this.** For previews, just close/reopen the PR.

## 7. Observability

`[observability] enabled` in `wrangler.toml` turns on Workers logs. Logs are
structured and contain no secrets and no PII beyond user IDs (spec §11). Tail
live with `wrangler tail`.
