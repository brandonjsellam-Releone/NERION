<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Reproduce every Nerion claim yourself

> **Purpose.** Nerion's credibility rests on *reproducible evidence*, not assertions. This page
> lists every verifiable claim with the **exact command** to check it and the **expected result**.
> If a command here does not produce the stated result, that is a bug — please file it.
>
> **Honesty contract.** Each row states its assurance level plainly. "Conformance-checked" means
> the implementation agrees with Nerion's *own* pinned vectors — **conformant is not validated**.
> "Machine-checked" / "property-checked" are evidence, **not** a proof of the whole implementation.
> Nerion is **UNAUDITED**, **not FIPS-140-3 / CMVP validated**, and **pre-FTO**. None of the
> commands below change that; they substantiate the *specific*, *bounded* claims in each row.
>
> **Branch note.** Items below marked *(branch: …)* currently live on an apex feature branch that
> is awaiting human merge to `main`; on merged `main` every command runs from the repo root.

## 0. Setup

```bash
git clone https://github.com/brandonjsellam-Releone/NERION.git && cd NERION
npm ci
# Rust paths additionally need a Rust toolchain (rustup); TLC needs a JRE; cargo-fuzz needs nightly.
```

## 1. Core correctness — tests + conformance

| Claim | Command | Expected | Assurance |
|---|---|---|---|
| Full test suite passes | `npm run gate` | lint(cleanroom)+format+typecheck+vitest all green (currently **463 tests / 72 files** on this branch; the count grows as apex branches merge) | tested · property-checked |
| Spec conformance | `npm run conformance` | **23/23 CONFORMANT** (checks C1–C23 against Nerion's pinned vectors) | conformance-checked |
| License/REUSE compliance | `~/.local/bin/reuse lint` (or `reuse lint`) | **REUSE 3.3 compliant** (every file carries license info) | reproducible |

## 2. Cryptographic byte-exactness (KAT)

| Claim | Command | Expected | Assurance |
|---|---|---|---|
| TS crypto matches pinned NIST-derived KATs | `npx vitest run crypto/test/kat.test.ts` | all pass (ML-KEM-1024 / ML-DSA-87 / SLH-DSA / SHA3 / HMAC-SHA-384 / AES-256-GCM byte-exact) | tested (KAT) |
| Rust hot-path matches the *same* KATs as the TS reference | `cd rust && cargo test` | 13 tests incl. `ts_kat_vectors_reproduce` (byte-exact vs `conformance/vectors/ps-kat.json`) | tested (cross-impl KAT) |

## 3. FIPS input-checking *(branch: apex/corpus-fips-ai-hardening)*

| Claim | Command | Expected | Assurance |
|---|---|---|---|
| Wrong-length ek/ct/σ/pk are rejected; ML-KEM implicit rejection is deterministic + same-length | `npx vitest run crypto/test/fips-conformance-negative.test.ts` | 14 tests pass (FIPS 203 §7.2/§7.3/§6.3, FIPS 204 σ/pk length) | tested · algorithm-compatible |
| FIPS 203/204/205 → Nerion clause map | read `docs/FIPS-CONFORMANCE-MAP.md` | every MUST/SHALL mapped to DELEGATED / TESTED / GAP with the `@noble` boundary stated | documented |

## 4. Formal verification — consensus accountable-safety *(branch: apex/beyond-apex-wave2)*

| Claim | Command | Expected | Assurance |
|---|---|---|---|
| Accountable-safety invariants hold (model-checked) | `cd docs/formal && java -cp /path/to/tla2tools.jar tlc2.TLC -config NerionConsensus.cfg NerionConsensus.tla` | **`Model checking completed. No error has been found.`** (144 distinct states) | machine-checked (abstraction) |
| …across the Byzantine spectrum | repeat with `-config NerionConsensus_6v1b.cfg` and `_7v2b.cfg` | no error (972 and 3 888 states) | machine-checked |
| …in CI on every change | see `.github/workflows/ci-formal.yml` | runs all three configs | machine-checked (CI) |
| Same invariants hold on the *real* code | `npx vitest run ledger/test/equivocation.property.test.ts` | pass (NoHonestEquivocation, detection-soundness, AccountableSafety over randomized inputs) | property-checked (implementation) |

## 5. Fuzzing — fail-closed on adversarial bytes *(branch: apex/beyond-apex-wave2)*

| Claim | Command | Expected | Assurance |
|---|---|---|---|
| Decoders/AEAD/HMAC/ML-KEM never panic on adversarial input | `rustup toolchain install nightly && cargo install cargo-fuzz && cd rust && cargo +nightly fuzz run fuzz_aead_open -- -max_total_time=45` (and `fuzz_hmac_verify`, `fuzz_mlkem_roundtrip`) | no crash/abort within the bound | fuzz (smoke; CI-wired in `ci-fuzz.yml`) |

## 6. Performance baseline *(branch: apex/pqc-sprint1)*

| Claim | Command | Expected | Assurance |
|---|---|---|---|
| Local dev latency baseline | `cd rust && cargo run --release --example manual_bench` | ML-DSA-87 sign ≈257 µs median; `decide()`-path composite ≈470 µs median / ≈711 µs p95 | **uncertified local baseline** |
| Criterion suite (rigorous) | `cd rust && cargo bench` (Linux CI) | statistical microbenchmarks | not yet collected on isolated hardware |

> **Performance honesty.** The numbers above are an **uncertified single-machine baseline** —
> the **sub-500 µs P99** target is **not yet substantiated** (p95/p99 exceed it; ML-DSA dominates
> the tail). Rigorous measurement on isolated hardware is explicitly future work, not a present claim.

## 7. What these commands do NOT prove

- **Not an external audit.** Internal multi-model review ≠ independent audit. (Inquiries submitted to OSTIF + OTF Security Lab.)
- **Not FIPS-140-3 / CMVP validated.** Algorithm alignment is not module validation.
- **Not a formal proof of the implementation.** Model checking covers an *abstraction*; property tests cover a *sampled* space.
- **Not freedom-to-operate.** The govern-the-verb design-around is engineering intent, not a legal non-infringement opinion.
- **Not production-ready.** Maturity is Local/Private dev.

See [ASSURANCE.md](ASSURANCE.md) for the authoritative claims matrix and
[ASSURANCE-EXTENDED.md](ASSURANCE-EXTENDED.md) for the per-guarantee engineering view.

*In one line: every command here substantiates a specific, bounded claim — and the rows above say
exactly how far each one reaches. Conformant is not validated; machine-checked is not implementation-proven;
a baseline is not a certified benchmark.*
