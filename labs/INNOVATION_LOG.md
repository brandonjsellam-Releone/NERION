<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion Labs — innovation log (append-only)

- **2026-06-23 · NZK-001 · hash-only PQ range proof (proof-elimination).**
  Sources: read-only `disclosure/src/zkrange.ts` (classical baseline 448·n bytes). Prototype ran
  (Node v24, `node:crypto` only): hash-only **23.6×** larger than classical (330 KB vs 14 KB @ n=32;
  660 KB vs 28 KB @ n=64), honest proof verifies, 1-byte tamper rejected. Council: DeepSeek (fix —
  "lower bound" overclaimed; homomorphism gap is the real kill reason), Grok (premature on size alone;
  optimized hash-Σ could reach ~4–6× — NZK-002), OpenAI (unreachable), Watsonx (FTO clean, no claims).
  **Verdict: KILL (unoptimized hash-only drop-in) + GRADUATE** to R&D (FRI/STARK or lattice; ADR-0022/B7).
  Branch `innovation/nzk-001-hash-range`. No prod code, no KAT/SuiteID change, no novelty/FTO claim.

- **2026-06-23 · NZK-002 · optimized hash-only (MPCitH/GGM) range proof.** Tested the NZK-001 Grok
  steelman. The GGM all-but-one seed tree is really implemented + verified + tamper-tested (N=256 & 4096).
  MODELED MPCitH size (±2×) is ~25–30× smaller than NZK-001's naive 23.6× → the naive blow-up is NOT
  fundamental; but the win **relocates to prover time** — at a practical ~1 s prover budget the modeled
  size is ~1.1–1.2× the *current* classical proof, sub-classical only at ~10 s. Two council rounds
  (Grok + DeepSeek; OpenAI/Gemini seats flapped): prover time is MODELED not measured; budget points are
  extrapolations; comparator bias — the real targets are Bulletproofs (<1 KB, non-PQ) + STARK/lattice (PQ),
  not the weak linear classical baseline. **Verdict: GRADUATE (qualified, NOT a competitiveness claim)** —
  R&D runs a PQ-disclosure bake-off (MPCitH vs STARK vs lattice; size×prover×verifier×assumptions; full
  impl + measured ms before any claim). Branch `innovation/nzk-002-mpcith` (stacked on nzk-001).

- **2026-06-23 · KER-001 · stateful vs stateless admission kernel (throughput).** STEP-4 FTO pre-screen
  **PARKED** the stateful-kernel framing (= in-gate cross-decision state = SIGA F5/commit-point territory
  the design-around avoids). Measured the FTO-clean reframe (real worker_threads + Atomics, Ed25519 proxy
  for ML-DSA-87): stateless admission scales 1.94× @P=2 → 6.08× @16 cores → **clears ≥2× trivially**, so a
  stateful kernel is unnecessary. Council: Watsonx (park is correct; not a non-infringement opinion —
  counsel-level claim analysis still needed), DeepSeek (proxy bias → **RETRACT "stateful is
  counterproductive"**; the plateau is proxy-fragile spinlock contention), Grok (KILL is narrow — stateful
  genuinely wins for global rate-limits/quotas/batching/caching, but those are cross-decision-state =
  FTO-parked → belong out-of-kernel). **Verdict: KILL (narrow) + GRADUATE** — Eng: confirm stateless
  parallel path; R&D+counsel: out-of-kernel policy layer + SIGA claim analysis. Branch
  `innovation/ker-001-stateless-throughput` (stacked on nzk-002). Demonstrated the FTO firewall parking a
  real hazard. No prod code, no novelty/non-infringement claim.

- **2026-06-23 · LED-001 · finality-certificate scaling (independent sigs vs aggregation).** Read-only
  intake `receipts/src/quorum.ts` (k independent ML-DSA-87 sigs — deliberately PQ-safe; threshold deemed
  classical). Measured (FIPS-204 real sizes; Ed25519 proxy verify; real+verified Merkle): independent cert
  is LINEAR — k=256 → ~1.16 MB / 256 verifies; **Merkle gives no size win** (measured); modeled STARK-agg
  (~44 KB constant) crossover k≈10. **Council REVERSED an over-eager KILL:** DeepSeek (STARK constant hides
  ≥Ω(k) prover time, possibly > block interval → "mirage"; "prohibitive >10" overclaim; 44 KB ±2–10×),
  Grok (status quo is the sound default — minimal TCB, fail-CLOSED vs alternatives' fail-OPEN, no DKG,
  churn-tolerant; k≈256 rare; gap is asymptotic), Gemini (503 unreachable — FIPS sizes standard but
  seat-unverified). **Verdict: NO KILL (independent-sig cert stays the right default) + CONDITIONAL
  GRADUATE** — evaluate STARK-agg (hard prover budget + fail-open) / threshold-lattice (DKG robustness)
  only IF Nerion targets a large-set + light-client + high-frequency-finality regime. Branch
  `innovation/led-001-finality-aggregation` (stacked on ker-001). **Lesson: the council prevents Innovation
  from manufacturing a false "win" — quantify the gap, but weigh it against the status quo's virtues.**

- **2026-06-23 · VRF-001 · PQ sortition vs classical ECVRF leader election.** Read-only intake
  `ledger/src/vrf.ts` (classical ECVRF-EDWARDS25519 — code already discloses the deliberate liveness/
  fairness residual; safety stays ML-DSA-87). Built a raw PQ hash-beacon sortition; measured: PQ + 0-byte
  proof + cheap, but **grindable** (target p=1/128: T tries → install prob {1:.008, 64:.40, 512:.98}). EC-VRF
  is classical but private + grind-resistant. **Council expanded the option space I prematurely closed:**
  DeepSeek (RETRACT the quorum-beacon mitigation — a *proposer* grinds the block hash pre-proposal; ≫512
  tries ⇒ ~100%; leader prediction → DoS/bribery), Grok (the real PQ contender = quorum-seed + PQ-VDF or PQ
  threshold beacon, which keeps grind-resistance AND is PQ — UNTESTED here; and whether *private* sortition
  is even load-bearing is unexamined). **Verdict: INCONCLUSIVE → REOPEN as VRF-002** (build quorum-seed +
  PQ-VDF sortition; settle the private-vs-public-unbiasable question from the ADR-0004 threat model). The
  classical VRF stays the pragmatic interim, but the PQ path is plausibly a VDF/threshold beacon, NOT "wait
  for a PQ VRF." Branch `innovation/vrf-001-pq-sortition` (stacked on led-001). Lesson: don't close the
  option space after the first (naive) construction — the council found the better PQ contender I skipped.
