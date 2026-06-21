# Apex Sprint Log

Per-cycle record of the apex backlog (`docs/APEX_SPRINT_BACKLOG.md`). One line per delivered item: branch + verification results.

- **2026-06-21 — A1 (Rust CI keystone)** — branch `apex/cycle-a1-rust-ci`. Added `gate-rust` CI job (toolchain pinned `dtolnay/rust-toolchain@29eef33…` SHA; `cargo fmt --check` + `cargo clippy --all-targets -D warnings` + `cargo test`, working-directory `rust/`) and a dedicated integration test `rust/tests/kat.rs` reproducing the committed `conformance/vectors/ps-kat.json` byte-exact for SHA3-256, SHAKE256 (outLen 16/32/64 — new 3rd-language parity, needed a `shake` crate dep + `shake256()` fn), HMAC-SHA-384, and AES-256-GCM. Node `gate` job left intact. Local verify ALL green: `cargo fmt --check` ✓, `cargo clippy --all-targets -- -D warnings` ✓, `cargo test` ✓ (13 tests: 9 unit + 4 KAT), `npm run gate` ✓ (368 tests), `npm run conformance` ✓ (23/23 CONFORMANT).
