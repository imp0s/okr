#!/usr/bin/env bash
# Build script invoked by `wrangler deploy` ([build].command in wrangler.toml).
# Produces:
#   build/worker/shim.mjs + wasm  — the Worker (worker-build)
#   dist/                          — the Leptos SPA static assets (trunk)
set -euo pipefail

echo "==> Building Worker (Rust -> WASM) via worker-build"
( cd crates/worker && worker-build --release )

echo "==> Building frontend SPA via trunk"
# Target HTML must precede `--release` (the flag otherwise consumes the path).
trunk build crates/frontend/index.html --release --dist dist

echo "==> Build complete: $(find dist -type f | wc -l) static asset(s)"
