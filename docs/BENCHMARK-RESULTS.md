<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion Benchmark Results — Local Developer Baseline

> **STATUS: rough single-machine baseline, NOT criterion-grade and NOT certified.**
> These numbers exist to give the team an order-of-magnitude feel for the PQ
> hot-path. They **must not** be cited in procurement, grant, or marketing
> material. Authoritative numbers come from `cargo bench --bench
> governance_roundtrip` run on a controlled Linux CI runner (see
> [`BENCHMARK.md`](BENCHMARK.md) for methodology and the criterion suite).

## How these were produced

The criterion suite (`rust/benches/governance_roundtrip.rs`) **compiles cleanly**
(`cargo check --benches` passes) but cannot *execute* on the maintainer's
windows-gnu dev toolchain: criterion's `html_reports` feature pulls
`plotters → windows-sys`, whose build step requires a functioning `dlltool` /
GNU binutils chain that is not available in that environment (see the build note
in `rust/src/lib.rs`).

To get a local signal anyway, a **dependency-free** harness
(`rust/examples/manual_bench.rs`) times the same primitives using only
`std::time::Instant` and the `polarseek-crypto` crate — no criterion, no
plotters, no windows-sys. It runs with:

```bash
cargo run --release --example manual_bench
```

## Environment

| Field | Value |
|---|---|
| CPU logical cores | 16 |
| OS / target triple | Windows 11 / `x86_64-pc-windows-gnu` |
| Rust toolchain | rustc 1.96.0 (stable-gnu) |
| Build profile | `--release` (optimized) |
| Methodology | median / min / p95 over N iterations after warm-up; single-threaded |

> A laptop/desktop windows-gnu build is a **pessimistic** environment for these
> primitives versus a tuned Linux server target. Treat these as an upper bound,
> not a best case.

## Results (median / min / p95)

| Operation | Median | Min | p95 | Iterations |
|---|---:|---:|---:|---:|
| ML-DSA-87 sign | 257.0 µs | 183.1 µs | 319.5 µs | 200 |
| ML-DSA-87 verify | 177.4 µs | 111.5 µs | 325.8 µs | 200 |
| ML-KEM-1024 keygen+encap+decap roundtrip | 377.7 µs | 220.2 µs | 944.8 µs | 200 |
| HMAC-SHA-384 (75 B) | 1.5 µs | 1.0 µs | 1.9 µs | 2000 |
| SHA3-256 (75 B) | 0.7 µs | 0.4 µs | 0.8 µs | 2000 |
| AES-256-GCM seal (75 B) | 0.5 µs | 0.4 µs | 0.6 µs | 2000 |
| **decide()-path composite** | **469.8 µs** | **298.9 µs** | **711.4 µs** | 200 |

The composite chains `sign → sha3 → verify → hmac → aes-seal` — i.e. the
per-action critical path **excluding** one-time-per-session KEM establishment.

## Honest interpretation vs. the sub-500 µs P99 target

- The composite **median (~470 µs)** is under the 500 µs target referenced in
  the federal SBIR materials, **but the p95 (~711 µs) is not** — and a true P99
  on this hardware would be higher still.
- The symmetric primitives (HMAC / SHA3 / AES) are sub-2 µs and are **not** the
  bottleneck. The cost is dominated by **ML-DSA-87 sign+verify** (~430 µs of the
  composite) plus tail variance, likely from allocation and OS scheduling jitter
  on a non-isolated Windows box.
- **Conclusion:** the sub-500 µs P99 claim is **not yet substantiated** and must
  not be stated as achieved. Paths to close the gap, in priority order:
  1. Measure on an isolated Linux server target (the real deployment profile).
  2. Reuse expanded ML-DSA keys / avoid per-call key expansion where the API
     allows.
  3. Pre-warm allocators / pin the hot-path thread; reduce per-op allocation.
  4. Consider the Rust hot-path for verify-heavy quorum aggregation.

This row is the single most important open performance item and is tracked for
the Linux-CI criterion run before any external performance statement is made.

## Reproducing

```bash
# Authoritative (Linux CI):
cd rust && cargo bench --bench governance_roundtrip

# Local windows-gnu signal (no criterion deps):
cd rust && cargo run --release --example manual_bench
```
