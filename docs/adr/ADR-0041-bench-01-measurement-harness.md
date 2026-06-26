<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0041 — BENCH-01: reproducible adversarial measurement harness

**Status: Accepted (starter / v0.1.0).** Design + initial implementation. This
ADR records a measurement-infrastructure decision, not a security result.
Everything BENCH-01 emits is **UNAUDITED / pre-FTO**; no audited, FIPS-validated,
production, or non-infringement claim is implied. Date: 2026-06-26.

## Context

Nerion's strategic mantra is **"measurement is the moat"**, yet all security and
performance claims are currently unaudited assertions. The fastest credibility
multiplier for the NLnet NGI Restack application and the OSTIF/OTF audit threads
is reproducible evidence rather than slide-deck claims.

This decision was put to the TRELYAN apex council. Asked for the *single* most
impactful "apex upgrade", **9 of 10 substantive seats chose BENCH-01** (seat #11
Moonshot/Kimi-K2, plus DeepSeek, Grok, OpenAI, Gemini, NVIDIA-Nemotron, WatsonX,
Hermes). The lone dissent (Mistral → ZK-PSR) conceded BENCH-01 wins when the
near-term driver is an audit/grant milestone — which it is. The strongest seats
(OpenAI/DeepSeek/Grok) steered the scope to **adversarial correctness first**, a
seeded corpus of attack traces with hard accept/reject verdicts, not a
performance dashboard.

## Decision

Ship BENCH-01 as a first-class, CI-gated measurement artifact:

1. A deterministic runner (`bench/run.mjs`) that exercises the **govern-the-verb**
   path — audience-bound permit-key derivation (HKDF-SHA-384) → salted intent
   commitment (SHA3-256) → permit sign/verify (ML-DSA-87) → revocation check →
   Merkle-anchored quorum receipt — over the real primitives.
2. An **adversarial corpus** (`wrongAudience`, `tamperedIntent`,
   `forgedSignature`, `suiteDowngrade`, `wrongKey`) where every attack trace
   MUST be rejected and every valid trace MUST be accepted. A violation fails the
   run immediately.
3. A **regression gate** (`tools/bench-gate.mjs`) that hard-fails CI on any change
   to deterministic invariants (signature scheme, artifact sizes, valid
   acceptance, adversarial rejection, inclusion-proof validity). Timings are
   advisory (machine-dependent) and not gated by default.
4. An **adapter interface** so the harness is implementation-agnostic. The
   shipped `noble-real` adapter measures the real upstream primitives; planned
   `dist-real` (Nerion's `crypto/src` wrappers) and `rust-ffi` (the Rust
   foundation) adapters enable Rust↔TS parity reporting.

This is a starter (v0.1.0). It models the verb path rather than calling the full
`planes`/`receipts`/`kernel` admission APIs; replacing the model with the real
APIs is the first roadmap item (`bench/README.md`).

## ADR numbering

main carries a gapless ADR-0001…0029. This ADR is allocated **0041** to stay
collision-free under the cross-branch reconciliation in progress at authoring
time:

| Range | Branch |
|------|--------|
| 0001–0029 | `main` (canonical) |
| 0030–0031 | `apex/innovation-sprint1` (vc-projection-impl, standards-binding-profile) |
| 0032–0034 | `apex/rnd-sprint1` (generator-H, zk-transcript, view-change-cert-chain) |
| 0035–0038 | `apex/sprint-A1-…` reconciliation (renumbered + deduped standards/vc ADRs) |
| **0041** | `apex/bench-01-harness` (this ADR) |

## Consequences

- **Positive:** converts "measurement is the moat" into infrastructure that every
  downstream frontier item (ZK-PSR, negative-oracle, GOV-PARAMS-BLINDNESS, SAF-2)
  can baseline against; a concrete, reproducible artifact for grant/audit
  reviewers; forces wire-frozen + cross-impl discipline; honesty-guardrailed by
  design (it publishes what is slow or broken rather than hiding it).
- **Honest caveats:** two harnesses ship. The primitive harness (`run.mjs`)
  measures ML-DSA-87 / SHA3 / HKDF over a *modelled* verb path. The real-path
  harness (`run-permit.mjs`) drives Nerion's *actual* `planes/src/permit.ts`
  (`issueBoundPermit` / `verifyPermitForAction`) via `dist/` — real code, real
  HMAC-SHA-384 permits, 7-class adversarial corpus — but does not yet reach the
  `receipts`/`kernel` admission path or cross-impl (Rust) parity. Timings are
  machine-dependent. UNAUDITED.

## Kill criterion

Scrap BENCH-01 if, after one month, it cannot reproduce a known action-gate
bypass / revocation mutation, or its results are not reproducible across
machines — i.e. if it degrades into a vanity dashboard disconnected from real
governance failures.

## References

- `bench/run.mjs`, `bench/adapters/noble-real.mjs`, `tools/bench-gate.mjs`,
  `bench/baseline.json`, `bench/README.md`, `.github/workflows/ci-bench.yml`.
- `crypto/src/sign.ts` (ML-DSA-87), `crypto/src/envelope.ts` (audience permit
  keys) — the primitives this harness mirrors.
- TRELYAN apex council panel verdict, 2026-06-26 (9/10 seats → BENCH-01).
