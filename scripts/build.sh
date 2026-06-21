#!/usr/bin/env bash
# Build script invoked by `wrangler deploy` ([build].command in wrangler.toml).
# Produces:
#   build/worker/shim.mjs + wasm  — the Worker (worker-build)
#   dist/                          — the Leptos SPA static assets (trunk)
set -euo pipefail

echo "==> Building Worker (Rust -> WASM) via worker-build"
( cd crates/worker && worker-build --release )

echo "==> Building frontend SPA via trunk"
# Run from the crate dir so trunk resolves okr-frontend as the root package
# (it runs `cargo metadata` in the CWD, which must not be the workspace root).
# Output to the repo-root ./dist that wrangler.toml serves as static assets.
( cd crates/frontend && trunk build index.html --release --dist ../../dist )

echo "==> Build complete: $(find dist -type f | wc -l) static asset(s)"
