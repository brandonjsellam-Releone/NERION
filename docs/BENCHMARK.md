# Nerion Performance Benchmarks

<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

## Overview

This document describes Nerion's benchmark suite and target performance goals
for federal procurement conversations.

The benchmark suite lives in `rust/benches/` and is driven by
[criterion.rs](https://bheisler.github.io/criterion.rs/book/), a
statistical micro-benchmarking framework for Rust that performs outlier
detection, warm-up runs, and confidence-interval reporting automatically.

**IMPORTANT — numbers in this document are pre-run ESTIMATES** derived from
published NIST pqc-project reference-implementation data. They have NOT been
measured on any specific Nerion deployment. Do not cite them in procurement
documents, RFP responses, or audit packages without running the benchmark suite
on the target hardware and reporting the measured values with full methodology
disclosure.

---

## Target Performance (Sub-500 μs P99 Governance Round-Trip)

The June 2026 DoD SBIR requirement for autonomous AI-agent governance is
**sub-500 μs P99 for a single governance round-trip** on commodity hardware
(Intel Xeon, AWS c5.xlarge or equivalent).

The Nerion hot-path round-trip comprises:

1. ML-KEM-1024 encapsulation (session key establishment, sender)
2. ML-DSA-87 signature (permit-intention commitment)
3. SHA3-256 receipt hash
4. ML-DSA-87 verification (quorum-seat receipt)
5. HMAC-SHA-384 PermitToken MAC
6. AES-256-GCM transport seal (decided payload)
7. ML-KEM-1024 decapsulation (receiver confirms shared secret)

Based on published NIST reference-implementation latencies, the combined
hot-path is estimated in the 600–800 μs range on a single core. Hardware
acceleration (AES-NI, AVX2, AVX-512), parallelism across quorum seats, and
pipelining can reduce this substantially. Actual measured values must be
reported before any procurement claim is made.

---

## Benchmark Methodology

| Attribute | Value |
|---|---|
| Tool | criterion.rs 0.5 (Rust) |
| Sampling | Warm-up 3 s + minimum 100 iterations, auto-extended for 95 % CI |
| Outlier detection | criterion IQR-based outlier classification (mild / severe) |
| Timing resolution | nanosecond (x86-64 TSC via `std::time::Instant`) |
| Platform target | commodity x86-64 (Intel/AMD), single-thread, no AVX intrinsics |
| Determinism | All benchmarks use fixed seeds — no OS RNG; fully reproducible |
| Interference | Close browser tabs and background processes; pin CPU frequency if possible |

---

## Expected Performance (Pre-Run Estimates)

The following table is derived from NIST pqc-project published numbers for
reference software implementations (no AVX2 acceleration) on Intel Skylake-class
hardware. These are starting-point estimates, not measurements.

| Operation | Expected P50 | Expected P99 | Source |
|---|---|---|---|
| ML-KEM-1024 Keygen | ~120 μs | ~160 μs | NIST pqc-project |
| ML-KEM-1024 Encap | ~150 μs | ~200 μs | NIST pqc-project |
| ML-KEM-1024 Decap | ~160 μs | ~210 μs | NIST pqc-project |
| ML-DSA-87 Keygen | ~200 μs | ~270 μs | NIST pqc-project |
| ML-DSA-87 Sign | ~400 μs | ~550 μs | NIST pqc-project |
| ML-DSA-87 Verify | ~180 μs | ~240 μs | NIST pqc-project |
| HMAC-SHA-384 (256 B) | ~1 μs | ~2 μs | Standard estimate |
| AES-256-GCM seal (256 B) | ~1 μs | ~2 μs | Standard estimate |
| SHA3-256 (256 B) | ~2 μs | ~3 μs | Standard estimate |
| **Governance Round-Trip*** | **~600 μs** | **~800 μs** | **Estimated** |

\* Single `permit_create` → `decide()` → `receipt_verify` chain; keygen
excluded (pre-provisioned keys assumed). KEM encap + DSA sign + DSA verify are
the dominant terms.

---

## Benchmark Suites

### `governance_roundtrip` (rust/benches/governance_roundtrip.rs)

End-to-end hot-path composite benchmarks.

| Benchmark name | Description |
|---|---|
| `ml_kem_1024_encap` | ML-KEM-1024 encapsulation only |
| `ml_kem_1024_decap` | ML-KEM-1024 decapsulation only |
| `ml_dsa_87_sign` | ML-DSA-87 sign (governance permit message) |
| `ml_dsa_87_verify` | ML-DSA-87 verify (quorum-seat receipt) |
| `hmac_sha384_256b` | HMAC-SHA-384 over 256 bytes |
| `aes_256_gcm_encrypt_256b` | AES-256-GCM seal over 256 bytes |
| `governance_roundtrip` | Full hot-path composite (steps 1–7 above) |
| `aes_gcm_payload_scaling/*` | AES-GCM seal at 64 / 256 / 1024 / 4096 B |
| `hmac_sha384_payload_scaling/*` | HMAC-SHA-384 at 64 / 256 / 1024 / 4096 B |

### `crypto_ops` (rust/benches/crypto_ops.rs)

Isolated primitive micro-benchmarks for regression detection.

| Benchmark group | Variants |
|---|---|
| `sha3_256/*` | 32 / 64 / 128 / 256 / 1024 B inputs |
| `shake256/*` | (32→32) / (64→48) / (128→64) B |
| `hmac_sha384/*` | tag_gen and tag_verify at 32–1024 B |
| `aes_256_gcm/*` | seal + open at 32–4096 B |
| `ml_kem_1024/*` | keygen_from_seed / encap / decap |
| `ml_dsa_87/*` | keygen / sign_short / sign_512b / verify_short / verify_512b / pk_bytes |
| `mlkem1024_roundtrip_ok` | Combined encap+decap helper |
| `permit_token_derivation` | SHA3-256 → HMAC-SHA-384 key-derivation chain |

---

## Running Benchmarks

```bash
# Full suite (both benches)
cd rust && cargo bench

# Single bench
cd rust && cargo bench --bench governance_roundtrip
cd rust && cargo bench --bench crypto_ops

# Filter to one benchmark by name substring
cd rust && cargo bench --bench crypto_ops -- ml_dsa_87

# One-shot timing without full criterion statistics (faster, less accurate)
cd rust && cargo bench --bench governance_roundtrip -- --profile-time 5
```

Results land in `rust/target/criterion/`.
HTML reports: `rust/target/criterion/report/index.html`.

---

## Reporting Results for Procurement

When including benchmark results in a DoD SBIR, RFP, or procurement document:

1. **Run on the reference platform** — AWS c5.xlarge (Intel Xeon Platinum 8275CL,
   single vCPU, 2 GiB RAM) or equivalent. Record exact instance type and
   `lscpu` / `cat /proc/cpuinfo` output.
2. **Pin CPU frequency** — disable turbo boost / frequency scaling
   (`cpupower frequency-set -g performance`) to reduce variance.
3. **Report P50 and P99** — criterion reports mean ± CI; extract percentiles
   from the raw sample CSV in `target/criterion/<bench>/base/sample.csv`.
4. **State toolchain** — `rustc --version` and `cargo --version`.
5. **State that numbers are measured** — never extrapolate from the estimates
   in this document.
6. **Do not state FIPS-certified or audited** — this crate has not completed
   a FIPS 140-3 validation or a third-party security audit as of 2026-06-24.

---

## Council PQC Notes (from Apex Sprint Backlog)

The following items from the council PQC review affect benchmark scope:

- **SLH-DSA bench** — `slh-dsa = "0.1"` is tracked in the apex backlog as a
  future addition. Once the crate stabilises, add
  `bench_slh_dsa_sign` / `bench_slh_dsa_verify` to `governance_roundtrip.rs`
  and the `bench_ml_dsa_87_ops` group in `crypto_ops.rs`. SLH-DSA is
  significantly slower than ML-DSA-87 (estimated 1–50 ms per sign depending on
  parameter set); include it in the P99 table before citing in procurement.
- **AVX2 / AVX-512 acceleration** — the `ml-kem` and `ml-dsa` crates may expose
  SIMD feature flags in future releases. Add a `features = ["avx2"]` variant
  bench once available to characterise the hardware-accelerated path.
- **Multi-seat quorum latency** — the `governance_roundtrip` bench measures a
  single seat. A 3-of-5 quorum adds parallel DSA verifications; model that as
  `verify_512b × 5 / 3` (parallelism factor) for procurement estimates.

---

## File Inventory

| File | Purpose |
|---|---|
| `rust/benches/governance_roundtrip.rs` | End-to-end hot-path composite benchmarks |
| `rust/benches/crypto_ops.rs` | Isolated primitive micro-benchmarks |
| `rust/Cargo.toml` | Adds `criterion` dev-dependency + `[[bench]]` entries |
| `docs/BENCHMARK.md` | This document |
