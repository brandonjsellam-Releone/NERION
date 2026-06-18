# rust/ — PolarSeek Rust hot-path foundation

The build spec mandates Rust for the latency-critical, constant-time hot path
(`crypto/`, `kernel/`, …). This crate is the **foundation**: a compiler-verified
Rust implementation of the PQ signature primitive (ML-DSA-87 / FIPS 204) and the
SuiteID identity, mirroring the TypeScript reference contract.

## Status (honest)

- **Compiles + type-checks here** via `cargo build` and `cargo test --no-run`,
  against RustCrypto's audited `ml-dsa` 0.1.1 + `sha3`.
- **Tests were NOT executed in this environment.** The build sandbox blocks
  running freshly-built binaries, so the test binary builds but cannot run here.
  Run `cargo test` on a normal machine to execute the round-trip assertions.
- Scope is deliberately small (signatures + hashing + SuiteID). Porting the
  KEM, kernel, capabilities, receipts, etc. is the next step — each must pass the
  cross-implementation contract in `../conformance`.

## Build / test

```bash
# (this repo is set up for a self-contained windows-gnu toolchain; see .cargo/config.toml)
cargo build           # compile + type-check
cargo test --no-run   # compile the test binary
cargo test            # run the tests (on a host that permits executing built binaries)
```

`.cargo/config.toml` pins `getrandom`'s `rdrand` backend only for the
`x86_64-pc-windows-gnu` target (a transitive build-time dep); it's unnecessary
on other targets. Keygen here is deterministic (FIPS KeyGen_internal from a
seed), so no OS entropy is used at runtime.

## What it provides

- `SuiteId` (`PS-1` / `PS-5`) mirroring `crypto/src/suites.ts`.
- `MlDsaKeypair::from_seed([u8;32])` — deterministic ML-DSA-87 keygen.
- `sign` / `verify` (round-trip + tamper-rejection tests authored).
- `sha3_256` — the PolarSeek commitment hash.

The cross-implementation goal: this crate (and any third-party build) must
satisfy the same SuiteID/wire contract validated by `../conformance`.
