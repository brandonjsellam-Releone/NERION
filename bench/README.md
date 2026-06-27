<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# BENCH-01 — reproducible adversarial measurement harness

> **"Measurement is the moat."** BENCH-01 turns Nerion's unaudited claims into
> reproducible, machine-readable evidence: a seeded corpus of valid **and**
> attack traces with hard accept/reject verdicts, plus primitive-cost metrics,
> wired to a CI regression gate.
>
> Picked as the single highest-leverage "apex upgrade" by 9 of 10 TRELYAN apex
> council seats (incl. seat #11, Moonshot/Kimi-K2). See
> [ADR-0041](../docs/adr/ADR-0041-bench-01-measurement-harness.md).

**Status:** starter / v0.1.0. UNAUDITED, pre-FTO. No audited, FIPS-validated,
production, or non-infringement claim is implied by any number it emits.

## What it measures

The harness models the **govern-the-verb** path over Nerion's real load-bearing
primitives and times each stage:

| Stage | Primitive |
|------|-----------|
| audience-bound permit-key derivation | HKDF-SHA-384 |
| salted intent commitment | SHA3-256 |
| permit signing / verification | ML-DSA-87 (FIPS 204, Cat-5) |
| revocation check | set membership |
| Merkle-anchored quorum receipt + inclusion proof | SHA3-256 tree |

It reports cryptographic artifact **sizes** (deterministic), per-stage
**timings** (advisory — machine-dependent), and **throughput**.

## Adversarial corpus (correctness first)

Every attack trace **must be rejected**; every valid trace **must be accepted**:

- `wrongAudience` — permit presented under a different audience (breaks HKDF audience binding)
- `tamperedIntent` — intent mutated after issuance (breaks the SHA3 commitment binding)
- `forgedSignature` — a flipped signature byte
- `suiteDowngrade` — a different SuiteID presented at verify
- `wrongKey` — verification under a different issuer key

A violation (valid rejected or attack accepted) fails the run immediately.

## Run it

```bash
npm run bench                      # primitive harness -> bench/report.json + summary
npm run bench:gate                 # gate it: fails on any size/security regression vs baseline
npm run build && npm run bench:permit   # real-path harness: drives the actual permit code in dist/
npm run bench:permit:gate          # gate the real-path report
npm run bench -- --update-baseline # regenerate a baseline (deterministic fields only)
npm run bench -- --permits=2000    # scale the workload
```

**Two harnesses.** `run.mjs` (primitive) measures ML-DSA-87 / SHA3 / HKDF directly
over a modelled verb path. `run-permit.mjs` (**real-path**) drives Nerion's ACTUAL
`planes/src/permit.ts` — `issueBoundPermit` / `verifyPermitForAction` via `dist/` —
with a 7-class adversarial corpus over the real defenses (MAC audience-binding,
action-hash binding, audience / expiry / effect / session checks, token tamper).

`bench/report.json` is generated (git-ignored). `bench/baseline.json` is
committed and holds only the **deterministic** fields (sizes + verdicts +
workload shape); timings are excluded so the gate is strict where it matters and
non-flaky where it doesn't.

## Adapters (the extension point)

`bench/run.mjs` is adapter-agnostic. `bench/adapters/noble-real.mjs` measures the
real primitives via the same upstream libs the protocol uses. Select with
`BENCH_ADAPTER=<name>`. Planned follow-on adapters:

- `dist-real` — Nerion's own `crypto/src` wrappers (via `npm run build`), so the
  harness measures protocol code, not just the underlying primitives.
- `rust-ffi` — the Rust foundation, for **cross-implementation parity** (Rust vs
  TS numbers side-by-side).

## Roadmap (starter → full BENCH-01)

- [x] **Real-path harness** (`npm run bench:permit`) drives the actual
      `planes/src/permit.ts` (`issueBoundPermit` / `verifyPermitForAction`) via `dist/`.
- [ ] Extend the real-path harness to the `receipts` / `kernel` admission + receipt APIs.
- [ ] `rust-ffi` adapter; publish Rust/TS parity deltas.
- [ ] Optional same-runner timing budget in CI (p95 thresholds).
- [ ] Sign each report (dCBOR) so published benchmark runs are verifiable.
- [ ] Expand the adversarial corpus from the conformance negative vectors.

## Kill criterion

Scrap BENCH-01 if, after one month, it cannot reproduce a known action-gate
bypass / revocation mutation, or its results are not reproducible across
machines — i.e. if it becomes a vanity dashboard disconnected from real
governance failures.
