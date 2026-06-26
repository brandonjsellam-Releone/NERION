<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion fuzzing

Coverage-guided fuzzing of the Rust hot-path primitives, complementing the
property/negative tests on the TypeScript side.

## Why

The crypto primitives must be **fail-closed on adversarial bytes**: AEAD open
returns `None` on any mismatch, HMAC verify returns `false`, and the ML-KEM
round-trip never crashes. A panic on attacker-controlled input is a
denial-of-service bug. Fuzzing drives random/structured inputs through these
functions and flags any panic/abort or memory error.

This complements:
- `crypto/test/decoder-fuzz.test.ts` — TS-side decoder fuzzing via `fast-check`.
- `crypto/test/fips-conformance-negative.test.ts` — FIPS input-rejection tests.

## Where

An **isolated** crate at `rust/fuzz/` with its own `Cargo.toml`. It is **not** a
member of the `rust/` package's build, so `cargo check`/`cargo test` in `rust/`
and `npm run gate` are completely unaffected by it. It depends on the crate under
test via `polarseek-crypto = { path = ".." }`.

Targets (`rust/fuzz/fuzz_targets/`):

| Target | Asserts |
|---|---|
| `fuzz_aead_open` | `aes256gcm_open` never panics; returns `None` on bad ct/tag/AAD |
| `fuzz_hmac_verify` | `hmac_sha384_verify` never panics; returns `false` on mismatch |
| `fuzz_mlkem_roundtrip` | `mlkem1024_roundtrip_ok` never panics on arbitrary seed material |

## Running (opt-in; out of the CI gate)

Fuzzing needs a nightly toolchain and `cargo-fuzz` (libFuzzer). It is deliberately
**not** part of `npm run gate` — it is a deepening activity, run on demand or in a
dedicated long-running job.

```bash
rustup toolchain install nightly
cargo install cargo-fuzz

cd rust
cargo +nightly fuzz run fuzz_aead_open        # Ctrl-C to stop; or -- -runs=1000000
cargo +nightly fuzz run fuzz_hmac_verify
cargo +nightly fuzz run fuzz_mlkem_roundtrip
```

Crashing inputs are written to `rust/fuzz/artifacts/<target>/`; reproduce with
`cargo +nightly fuzz run <target> rust/fuzz/artifacts/<target>/<crash>`.

## Corpus & seeds

`cargo-fuzz` maintains an evolving corpus under `rust/fuzz/corpus/<target>/`
(gitignored). Seed it with known-good inputs (e.g. a valid 32+12+ct AEAD blob) to
speed coverage. Keep interesting minimized crash-reproducers under version control
*only* after confirming they contain no secret material.

> **Status.** The harness is provided as a ready-to-run skeleton; it has not yet
> been executed in CI here (nightly + cargo-fuzz are not provisioned in this
> environment). Wiring a scheduled fuzz job is a follow-up.
