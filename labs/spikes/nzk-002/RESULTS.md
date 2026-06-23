<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# NZK-002 — RESULTS (GGM measured; total size + prover time MODELED)

> **TOY / MOCK — UNAUDITED, pre-FTO.** No novelty/patentability/non-infringement claim. © TRELYAN.
> Read the **measured-vs-modeled** split below before quoting any number.

## Question
Does an **optimized** hash-only range proof — fewer repetitions + a GGM "all-but-one" seed tree (the
Picnic / MPC-in-the-head technique) — overturn **NZK-001**'s naive **23.6×** blow-up and reach the
~4–6× region a council seat (Grok) argued for?

## Measured vs modeled (the honesty boundary — flagged by DeepSeek + Grok)
| Quantity | Status |
|---|---|
| GGM all-but-one seed tree: honest reconstruct + 1-byte-tamper rejection | **MEASURED** (self-test OK at N=256 and N=4096) |
| GGM opening size (depth seeds + 1 commitment) | **MEASURED** (real serialized bytes) |
| Single SHAKE256 op cost (`hashMs`) | **MEASURED** (0.00245 ms/op, this host) |
| **Total proof size** (GGM-open + commit + broadcast, ×τ×preproc) | **MODELED**, ±~2× |
| **Prover wall-clock** (τ·N·partyHashes·hashMs) | **MODELED / extrapolated** — *not* an end-to-end benchmark; real per-party cost is higher and may shift crossing points 2–5× |

## Measured GGM primitive (the real, load-bearing mechanism)
```
GGM self-test depth=8  (N=256):  OK   (7.96 ms/op)
GGM self-test depth=12 (N=4096): OK   (146.7 ms/op)
```
Honest all-but-one opening reconstructs every leaf except the punctured one; a 1-byte flip of any
sibling seed is detected. This is the genuine efficiency mechanism that compresses cut-and-choose.

## Modeled size + the size↔prover tradeoff (illustrative — ±2× size, prover extrapolated)
Size-optimal (prover **unconstrained** — the over-eager view the council flagged):
- n=32 → ~13.7 KB (~1× classical), n=64 → ~22.9 KB (~0.8×) — but at **N=4096 parties** (impractical prover).

Min modeled size **subject to a prover-time budget** (the realistic operating point):
| prover budget | n=32 | n=64 |
|---|---|---|
| 100 ms | ~1.7× classical | ~1.9× |
| 1 s | ~1.2× | ~1.1× |
| 10 s | ~0.9× | ~0.8× |

Optimized hash-only is **~25–30× smaller than NZK-001's naive 23.6×**. Crossing points are illustrative
(both models carry uncertainty; a full implementation may move them 2–5×, and a real bake-off would add
verifier-time and parallelization axes this spike does not model).

## Council adjudication (two rounds)
- **Round 1 (Grok):** the size optimum needs ~4096 virtual parties — an impractical-prover regime; the
  "size win" **relocates to prover time**, not removed.
- **Round 1 (DeepSeek):** ±2× straddles the baseline; prover time was unquantified; **comparator bias** —
  14 KB is a weak non-SOTA *linear* proof; the real targets are **Bulletproofs (<1 KB, non-PQ)** and
  **STARK / lattice (PQ)**.
- **Round 2 (this revision):** both confirm **no blocker**. Remaining fixes (applied here): label prover
  time MODELED not measured; budget points are extrapolations; keep ±2× visible; don't read "~classical"
  as "competitive."

## Verdict — GRADUATE (qualified; explicitly NOT a competitiveness claim)
1. **NZK-001's naive 23.6× is NOT fundamental.** MPCitH/GGM sidesteps it (~25–30× smaller). NZK-001's
   homomorphism-gap KILL of the *naive Σ-protocol* family stands; the broader "hash-only is hopeless"
   reading is **refuted**.
2. **The win relocates to prover time.** At a practical ~1 s prover budget the modeled size is ~1.1–1.2×
   the *current* classical proof; sub-classical only at ~10 s prover budgets.
3. **"~classical" ≠ "competitive."** Against the right targets the modeled proof is still ~20–40× larger
   than a Bulletproof and must be measured against STARK/lattice for the PQ decision.
4. **GRADUATE to R&D — a properly-scoped PQ-disclosure bake-off:** MPCitH vs STARK vs lattice, scored on
   **size × prover-ms × verifier-ms × assumptions**, benchmarked against **Bulletproofs + STARK**,
   requiring a **full implementation with measured prover/verifier ms (±20%)** before ANY "competitive"
   claim. Routes into the existing ADR-0022 / B7 PQ-commitment-migration track.

## Honesty caveats
Toy; the GGM tree is real but the surrounding MPC soundness is modeled, not implemented. Total size and
prover time are models; only the GGM primitive, its opening size, and the single-hash cost are measured.
No claim of competitiveness, audit, production-readiness, novelty, or freedom-to-operate.
