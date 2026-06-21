#!/usr/bin/env bash
# Build script invoked by `wrangler deploy` ([build].command in wrangler.toml).
# Produces:
#   build/worker/shim.mjs + wasm  — the Worker (worker-build)
#   dist/                          — the Leptos SPA static assets (trunk)
set -euo pipefail

echo "==> Building Worker (Rust -> WASM) via worker-build"
# Relax the release profile for the Worker build only. wasm-bindgen needs the
# `__wbindgen_externref_table_alloc` runtime intrinsic to wire up the `worker`
# crate's `catch` wrappers, which route through an externref table because
# rustc >=1.82 forces the wasm `reference-types` feature on (and it cannot be
# disabled on stable). Fat LTO + symbol stripping + opt-level="z" dead-code-
# eliminate that intrinsic before wasm-bindgen runs, causing
# "externref table required for catch wrappers". Disabling LTO/strip and easing
# opt-level keeps the intrinsic present. (The frontend build below is
# unaffected and stays fully optimized.)
(
  cd crates/worker
  export CARGO_PROFILE_RELEASE_LTO=false
  export CARGO_PROFILE_RELEASE_STRIP=false
  export CARGO_PROFILE_RELEASE_OPT_LEVEL=1
  export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16
  worker-build --release
)

echo "==> Building frontend SPA via trunk"
# Run from the crate dir so trunk resolves okr-frontend as the root package
# (it runs `cargo metadata` in the CWD, which must not be the workspace root).
# Output to the repo-root ./dist that wrangler.toml serves as static assets.
( cd crates/frontend && trunk build index.html --release --dist ../../dist )

echo "==> Build complete: $(find dist -type f | wc -l) static asset(s)"
