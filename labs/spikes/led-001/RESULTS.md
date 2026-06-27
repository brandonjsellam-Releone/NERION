<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# LED-001 — RESULTS (status quo is sound; a quantified, regime-bounded scaling gap)

> **TOY / MOCK — UNAUDITED, pre-FTO.** No novelty/patentability/non-infringement claim. © TRELYAN.
> **The headline verdict was de-escalated from a "KILL" after council review** — see below.

## Question
Nerion's finality / quorum cert is **k independent ML-DSA-87 signatures** (`receipts/src/quorum.ts`), a
deliberate PQ-safe choice (the code notes a real threshold signature "would be classical, not
post-quantum"), so the cert is **linear in k**. What does that cost as the validator set scales, and does
a PQ-sound aggregation obsolete it?

## Measured (ML-DSA-87 sizes FIPS-204 exact; verify time Ed25519 PROXY; Merkle real+verified)
| k (quorum) | independent cert (full / minref) | verifies | Merkle-agg | STARK-agg (model) | threshold-lattice (model) |
|---|---|---|---|---|---|
| 4 | 28.2 / 18.1 KB | 4 | 18.2 KB | 43.9 KB | 4.5 KB |
| 16 | 112.8 / 72.3 KB | 16 | 72.5 KB | 43.9 KB | 4.5 KB |
| 67 | 472.3 / 302.8 KB | 67 | 303.0 KB | 43.9 KB | 4.5 KB |
| 256 | 1804.8 / 1156.8 KB | 256 | 1157.1 KB | 43.9 KB | 4.5 KB |

- **Independent cert is linear in k** (real ML-DSA-87 sizes). Merkle inclusion is real (self-test OK, tamper rejected).
- **Merkle hashing gives NO cost reduction** (measured): the root only indexes the sigs; a verifier still
  needs all k sigs present and runs k verifications.
- **Modeled crossover:** a succinct STARK-of-signatures (~constant) beats the flat list above **k ≈ 10**.

## Council review — the KILL was wrong; here is the corrected reading
- **DeepSeek (fix-first):** the STARK "constant ~44 KB" **omits prover cost**. Proving k ML-DSA-87 verifies
  in-circuit is ≥ Ω(k) with large constants — a back-of-envelope for k=256 (≈10⁵–10⁶ gates/verify ×256 ≈
  10⁷–10⁸ gates; ~10⁶–10⁷ gates/s provers) is **seconds to minutes**, plausibly **exceeding a fast-finality
  block interval** → if so, the small size is a *mirage*. The 44 KB itself is a best-case model, ±2–10×
  (so the crossover is really **k ≈ 10–100**). "Linear-prohibitive beyond ~10" is an **overclaim**.
- **Grok (status quo is the sound default):** independent sigs preserve a **minimal trusted computing base**
  and **fail CLOSED** on any malformed signature; STARK/threshold alternatives add a heavy/centralizing
  prover or a fragile DKG and can **fail OPEN** on a broken aggregation proof. The DKG degrades *exactly*
  when the set is largest/most adversarial. k≈256 is rare; 1.16 MB is <0.3% of a typical block and verifies
  in ~ms; each sig is independently/streaming-verifiable; light-clients are secondary.
- **Gemini:** seat unreachable (503) this run — the FIPS-204 ML-DSA-87 sizes (sig 4627 B, pk 2592 B) are
  the published standard values but were **not** independently seat-verified here.

## Verdict — NO change recommended to the default; a CONDITIONAL, regime-bounded graduation
- **The independent-signature finality cert is NOT killed.** It is a sound, deliberately PQ-safe design with
  real virtues — minimal TCB, fail-closed, coordination-free, churn/eclipse-tolerant, streaming-verifiable.
  For the **common regime** (validator sets up to the low hundreds; bandwidth/verification not the scarce
  resource) it is the right choice.
- **The measured gap is real but regime-bounded.** Linear cost only bites when **all** of: very large
  validator sets (hundreds+), **and** bandwidth/storage-constrained or light-client-heavy verification,
  **and** high-frequency finality.
- **GRADUATE (conditional) to R&D:** *if* Nerion ever targets that regime, evaluate (a) STARK-aggregated
  finality **under a hard prover-time budget + an explicit fail-open analysis**, and (b) threshold-LATTICE
  signatures **with a DKG-robustness analysis** (and reconcile the `quorum.ts` "threshold = classical"
  comment with current threshold-lattice research — which exists but is immature). Otherwise, keep the
  independent-sig cert. **Do not replace the default on the strength of size alone.**

## Honesty caveats
Ed25519 ≠ ML-DSA-87 verify time (proxy understates the real per-sig burden); the STARK size + prover-time
figures are coarse models (±2–10×), not implementations; threshold-lattice is a research-bet without a
concrete protocol here. Sizes for the independent cert are real; everything about the alternatives is a
model. No competitiveness, audit, production-readiness, novelty, or FTO claim.
