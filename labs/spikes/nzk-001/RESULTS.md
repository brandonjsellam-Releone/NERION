<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# NZK-001 — RESULTS (executed + measured)

> **TOY / MOCK — UNAUDITED, pre-FTO.** The prototype is a throwaway cost-model, not a vetted
> protocol; its zero-knowledge and soundness are **not** cryptographically reviewed. Measured
> bytes/ms are real (real SHAKE256 work + real serialization). This note makes **no** novelty,
> patentability, or non-infringement claim. © TRELYAN.

## Question
Could a **hash-only** (post-quantum, SHAKE256) range proof replace Nerion's classical
**ristretto255** ZK range proof in `disclosure/src/zkrange.ts` — the known **non-PQ residual**
(ADR-0022 / backlog B7)? Pre-registered KILL thresholds (to be worth a drop-in): proof **≤ 2 KB**
AND prover **≤ 100 ms** AND verifier **≤ 50 ms**.

## Method
- **Prototype** (`prototype.mjs`, `node:crypto` only, imports nothing from the repo): a hash-only
  range proof modelled as per-bit cut-and-choose **booleanity-consistency** (λ=128 parallel reps),
  Merkle-anchored bit commitments, Fiat–Shamir, two sub-statements (amount + diff) mirroring the
  classical construction.
- **Classical baseline** derived from the real source: per subproof = n bits × (1 commitment[32 B] +
  BitProof[6×32 B]) = 224n; full proof (amount+diff) = **448·n bytes** on ristretto255.
- **Measured:** serialized proof bytes, prover/verifier ms (avg of 30), correctness, 1-byte-tamper rejection.

## Measured result (ran 2026-06-23, Node v24)
| n (bits) | hash-only (PQ) | classical (ristretto255) | blow-up | prove | verify | honest verifies | tamper rejected |
|---|---|---|---|---|---|---|---|
| 32 | 337,832 B (~330 KB) | 14,336 B (14 KB) | 23.6× | 56 ms | 19 ms | ✅ | ✅ |
| 64 | 675,572 B (~660 KB) | 28,672 B (28 KB) | 23.6× | 113 ms | 40 ms | ✅ | ✅ |

Against the pre-registered **≤ 2 KB** bar the hash-only proof misses by ~165× → **fails the size threshold.**

## Council adjudication (STEP 7)
- **DeepSeek — fix-first:** measurement credible; **"conservative lower bound" was overclaimed** — it
  bounds *this* cut-and-choose design, not *all* hash-only ZK proofs (STARKs/MPCitH scale better). The
  load-bearing kill reason is the **architectural homomorphism mismatch**, not the 23.6× number.
- **Grok — verdict premature on size alone:** λ=128 + Merkle is unoptimized; reduced reps (~40–60) +
  vector commitments (O(nλ)→O(λ log n)) could land ~80–120 KB for n=64 (~4–6×). Steelman: no new
  hardness assumption, reuses SHAKE256, simpler/more auditable than lattice/FRI — could win where
  proofs are offline or PQ signatures already dominate transport.
- **OpenAI — seat returned no output (logged unreachable).**
- **Watsonx — FTO clean, low-severity revise:** generic public-domain primitives, no competitor
  material referenced, no novelty/patentability/non-infringement claims. No FTO blocker; a full patent
  landscape is a counsel-level step, out of scope for a spike.

## Verdict (revised per council) — KILL (qualified) + GRADUATE
- **KILL** the *unoptimized, naive hash-only Σ-protocol drop-in*: it fails the size bar (~24× larger,
  and ~165× over the 2 KB target) while the classical proof it would replace is **both smaller and
  already zero-knowledge**.
- **Durable finding (the real reason, not the byte count):** hash commitments lack the **additive
  homomorphism** that makes the classical proof's linear-binding check (`Σ Cᵢ·2ⁱ == C`) cheap.
  Recovering ZK **and** linear-binding over hashes forces either a **circuit proof** (FRI/STARK,
  polylog) or **algebraic structure** (lattice). The 23.6× figure is **design-specific and loose** —
  it is *not* a proven lower bound for all hash-only designs.
- **GRADUATE to R&D** (pointer + numbers; R&D formalizes, Engineering would re-implement clean):
  1. **Primary PQ path** — succinct hash-based (FRI/STARK, polylog proof) or **lattice** range proofs,
     evaluated under the existing ADR-0022 / B7 PQ-commitment-migration track.
  2. **Hedge (NZK-002 candidate)** — an *optimized* hash-Σ (reduced repetitions + vector commitments)
     for offline / PQ-signature-dominated transport, to test Grok's ~4–6× steelman before the naive
     family is fully abandoned.

## Honesty caveats
Toy, not ZK, not audited; the opened repetitions leak the bit. The size number models a hash-only
transcript's cost and is conservative *for this design only*. Classical baseline is the repo's O(n)
bit-decomposition proof (not a logarithmic Bulletproof), so the comparison is meaningful **within the
current codebase**, not as a universal "hash vs. algebra" benchmark.
