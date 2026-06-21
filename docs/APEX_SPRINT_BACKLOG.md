# Nerion 21-Day Continuous-Upgrade Sprint — Sequenced Backlog (2026-06-20 → 2026-07-11)

> Marching orders for the **Team Apex** sprint (see [APEX_COUNCIL.md](./APEX_COUNCIL.md)).
> Produced by the Cycle-1 multi-agent survey (6 dimensions, 54 candidates). The scheduled
> task `nerion-apex-sprint` works the next item each cycle, council-reviewed, on a branch.
>
> **Sort key:** value desc → risk asc → effort asc (S<M<L). **TRACK A (autonomous-safe)** =
> auto-implement on a branch, merge only when `npm run gate` + `npm run conformance` stay green.
> **TRACK B (human/audit-gated)** = ADR / design-doc only; no behavior or KAT change without council review.
>
> **Hard invariant for every Track-A merge:** gate + conformance stay green and **no edit touches
> `crypto/src/suites.ts` SuiteID `Ps1` or `conformance/vectors/ps-*.json`** (the wire-tag/KAT freeze
> that keeps 23-of-23 conformance and the FTO design-around intact).

## SHIP FIRST
**A1 — Rust CI job** (`cargo fmt --check`, `clippy -D warnings`, `cargo test` vs committed KATs).
The keystone: every Rust-parity/KAT item (A13/A16/A21/A23/A24/A25/A29/A41) is silently regressible until this gate exists. Value 5 / risk 1 / effort S.

## TRACK A — AUTONOMOUS-SAFE

### Wave 1 (Days 1–7)
| Rank | Title | V/R/E | Definition of Done |
|---|---|---|---|
| **A1** | Rust CI job (fmt/clippy/test) | 5/1/S | `gate-rust` green on PR; `cargo test` reproduces `ps-kat.json`; red on drift. |
| A2 | Fuzz decoders (decodeCbor/COSE/permit/receipt never panic) | 5/1/M | fast-check over random/truncated bytes; value or typed error, never uncaught throw/hang. |
| A3 | Local pre-commit secret guard (gitleaks/regex) | 5/1/S | hook blocks staged `.env`/key patterns incl `git add -f`; `.gitleaks.toml` committed. |
| A4 | gitleaks secret-scan CI job (tree + history) | 5/1/S | CI job (SHA-pinned) fails PR on hit; green on clean tree. |
| A5 | Reconcile stale `THREAT_MODEL.md` status → current tests / 23-of-23 / built planes | 5/1/S | status + §0 + §7-R1 reflect reality; §3 trust-boundaries untouched. |
| A6 | Stryker mutation testing (crypto/disclosure/receipts) | 5/2/M | `npm run mutation`; baseline in ASSURANCE.md; opt-in (non-gating). |
| A7 | SPDX SBOM via `reuse spdx` | 5/2/M | `nerion.spdx` committed + regen note; coherent vs 188/188 REUSE; referenced from AUDIT_PACKAGE/README. |

### Wave 2 (Days 8–14)
| Rank | Title | V/R/E | Definition of Done |
|---|---|---|---|
| A8 | Pin GitHub Actions to 40-char SHAs | 4/1/S | all actions SHA-pinned with `# vX` comment; CI green. |
| A9 | Property-test VRF determinism/uniqueness/key-binding | 4/1/S | fast-check; verify rejects any 1-byte tamper of π/α/pk. |
| A10 | Tests for `sortition.selectLeader` (zero coverage today) | 4/1/S | determinism, membership, stake-weighting, permutation stability. |
| A11 | Property-test Merkle inclusion (completeness + tamper-soundness) | 4/1/S | rejects forged root, wrong index, 1-byte leaf/path tamper. |
| A12 | Negative ledger tests (sub-2/3, cross-epoch, dup-vote, cross-prevHash certs) | 4/1/M | `verifyViewChangeCert` proven to REJECT each; dedup + BigInt cross-multiply exercised. |
| A13 | Reproduce SHAKE256 KAT in Rust (3rd-language parity) | 4/1/S | reproduces ps-kat outLen 16/32/64; CI green (needs A1). |
| A14 | cargo-fuzz: AEAD open + HMAC/permit verify (never-panic) | 4/2/M | hostile inputs run clean; no panic/OOB. |
| A15 | Expand govern-the-verb negative oracle (resource/top-level/nested/session-meta) | 4/2/M | injection-site dimension in `ps-negative.json`; kernel still verb-only. |
| A16 | Negative/tamper KAT vectors cross-impl (TS/Rust/Python) | 4/2/M | flipped-tag AEAD, bad HMAC, wrong-alg COSE MUST fail in all 3 runners. |
| A17 | Dependabot + report-only OSV/npm-audit CI step | 4/2/S | `.github/dependabot.yml`; non-blocking vuln scan. |
| A18 | Record Azure-ID history-purge resolution (no delete/recreate) | 4/1/S | gitleaks `--all` corroborates clean history; destructive plan closed. |
| A19 | Range-validate `certRound` in `verifyViewChangeCert` | 3/2/S | additive guard; negative test added. |
| A20 | Wire equivocation detect→verify→slash into gossip (or document) | 4/3/M | conflict path calls detect/verify(/slash) OR documented operator action. |

### Wave 3 (Days 15–21)
| Rank | Title | V/R/E | Definition of Done |
|---|---|---|---|
| A21 | Port HKDF-SHA-384 + audience-bound PermitToken to Rust (needs A23) | 5/2/L | byte-exact; KAT reproduces TS permit bytes. |
| A22 | Wire or remove unused `subtle` dep | 2/1/S | constant-time compare via `ConstantTimeEq`, or removed; clippy clean. |
| A23 | Reproduce dCBOR canonical-encoding KAT in Rust | 4/3/M | reproduces ps-kat `cbor[]` hex; prereq for A21. |
| A24 | Reproduce SLH-DSA-SHAKE-256f keygen KAT (pubkey SHA3) in Rust | 3/2/M | reproduces pubkey SHA3 from 96-byte seed. |
| A25 | Cargo SBOM (cyclonedx) + cargo-audit in Rust CI | 3/1/S | RustSec scan + machine-readable Rust SBOM. |
| A26 | Property-test settlement credits (conservation/non-negative/replay) | 3/1/S | conserve value, never negative, replay idempotent/rejected. |
| A27 | Property-test equivocation detection over random STH sets | 3/1/S | honest never flagged; double-signer flagged once; no false positives. |
| A28 | Property-test canonical-CBOR injectivity/round-trip | 3/1/S | deterministic encode, decode∘encode byte-identical, no collisions. |
| A29 | Rust-parity audit: BigInt finality/quorum + VRF point validation | 3/2/M | no f64 finality; identical RFC-9381 validation + ≥2/3 direction. |
| A30 | Conformance vector for round-skip cert-chain invariant (after B3) | 3/2/M | complete chain accepted; missing intermediate rejected; cross-impl. |
| A31 | CI coverage report (vitest --coverage) + per-module threshold | 3/1/S | untested export becomes a visible signal; no behavior change. |
| A32 | CycloneDX SBOM as CI artifact | 3/1/S | `sbom.cdx.json` artifact per run; report-only. |
| A33 | CODEOWNERS (+ document branch protection) | 3/1/S | routes crypto/governance paths; protection steps documented. |
| A34 | NGI/NLnet ecosystem acknowledgment ("applying to", NOT "funded by") | 3/2/S | honesty bar preserved (call opens ~Sept 2026). |
| A35 | SLSA build provenance via OIDC for releases | 3/2/M | narrow `id-token: write` emits signed provenance. |
| A36 | Finish Phase-2 Nerion rename of NON-protocol ids (pkg/crate/module/bundle) | 3/3/L | **SuiteID `Ps1` + ps-*.json untouched**; full gate+conformance re-verify. |
| A37 | Adversarial verifier-side ZK test vectors | 3/1/M | `verifyBelow` false/throws on identity/low-order pts, zero-scalar, forged split, cross-statement replay. |
| A38 | Fix stale `rust/README.md` "tests were NOT executed" | 2/1/S | doc-only; Status updated to passing KAT reproduction. |
| A39 | Document the assurance matrix in `docs/ASSURANCE.md` | 3/1/S | guarantee × artifact matrix. |
| A40 | Document round-skip & set-binding caveats in STATUS/SECURITY | 3/1/S | three consensus caveats stated for auditors. |
| A41 | `no_std` + alloc for the Rust crate | 3/3/L | KAT loader behind `std` feature; CI green. |
| A42 | CONTRIBUTING/DCO polish (optional; do last) | 1/1/S | optional PR template / DCO check. |

## TRACK B — HUMAN/AUDIT-GATED (ADR / design only; no autonomous KAT/behavior change)
| Rank | Title | V/R/E | Definition of Done |
|---|---|---|---|
| **B1** | ADR + KAT: pin generator-H provenance (H≠G/identity startup invariants) | 5/2/S | pinned-H KAT + load-time invariant *specified*, council-approved before gated KAT lands. |
| B2 | ADR: special-soundness + HVZK + FS transcript-completeness for dual-range OR-proof | 5/2/M | paper argument; per-bit challenge binding sufficiency (or tighten to single transcript). |
| B3 | View-change cert-chain to close LEDGER-007 round-skip gap | 5/4/L | chained ViewChangeCert; skip cost linear in rounds; conformance regen plan (impl deferred). |
| B4 | ADR: reconcile ADR-0013 amount domain + v:2 receipt-body wiring | 5/3/L | canonical amount domain end-to-end; kernel-admission commitment check; M3/M4 grant deliverable. |
| B5 | Bind validator-set id/epoch into votes/attestations/equivocation proofs | 4/4/L | `setId(sorted[pubkey,stake],epoch)` folded into 3 preimages; cross-epoch consent-transfer closed. |
| B6 | ADR: PQ-sound set-membership (SHA3 Merkle) bound into FS transcript | 4/3/L | reuses translog merkle; fenced behind `allowUnauditedZk`; routes to ZK audit. |
| B7 | ADR: PQ-commitment migration preserving v:2 SHA3 binding; QROM note | 4/4/L | migration design; QROM-vs-ROM residual flagged; research-track. |
| B8 | Epoch/finalized-checkpoint guard in slash() against long-range/stale slashing | 3/3/M | epoch-bound on EquivocationProof + unbonding window. |
| B9 | Freeze canonical ML-DSA-87 secret-key KAT (seed vs expanded encoding) | 3/4/M | cross-impl decision recorded as ADR with FTO/interop implications. |
| B10 | Enable GitHub-side secret scanning + push protection | 4/1/S | repo settings toggles ON (admin token); documented in SECURITY.md. |
| B11 | Rotate local live secrets; split `.env`; AKIA→STS; custody via Key Vault | 4/3/M | maintainer-driven (touches live credentials). |

## Dependency edges
A1 gates A13/A16/A21/A23/A24/A25/A29/A41. A23 gates A21. A30 depends on B3's ADR. A20 reuses A12's fixtures.
