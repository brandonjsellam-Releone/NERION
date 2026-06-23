<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# KER-001 — RESULTS (FTO-parked at pre-screen; FTO-clean reframe measured)

> **TOY / MOCK — UNAUDITED, pre-FTO.** This is engineering screening, **not** a legal/non-infringement
> or novelty determination (counsel-only). Ed25519 stands in as a **proxy** for the real ML-DSA-87
> admission signature, so absolute ops/sec are a *shape*, not a protocol benchmark. © TRELYAN.

## STEP-4 FTO PRE-SCREEN — the headline action
The backlog framed KER-001 as *"a stateful-yet-equivalent admission kernel for ≥2× throughput."* A
**stateful admission kernel = in-gate cross-decision state**, which is precisely the SIGA F5 /
commit-point-gate territory that Nerion's stateless *govern-the-verb* model deliberately designs around.
Per the charter the spike is **PARKED, not built** — building a stateful-kernel prototype could
contaminate the clean-room design-around. **Watsonx (FTO seat): the park is the correct call**; staying
stateless is a viable design-around — but this is engineering caution, *not* a confirmed non-infringement
opinion (needs counsel-level SIGA claim analysis + prior-art search).

We instead measured the **FTO-clean question** that motivated the bet: *is a stateful kernel even
necessary — does stateless admission already clear ≥2× throughput?*

## Measured throughput (real worker_threads + Atomics; 16 logical cores; Ed25519 proxy)
| P (workers) | stateless ops/s (speedup) | stateful, shared-state ops/s (speedup) |
|---|---|---|
| 1 | 9,900 (1.0×) | 9,743 (1.0×) |
| 2 | 19,187 (**1.94×**) | 18,492 (1.90×) |
| 4 | 34,554 (3.49×) | 33,168 (3.40×) |
| 8 | 52,340 (5.29×) | 51,516 (5.29×) |
| 16 | 60,201 (6.08×) | 51,510 (5.29×, **plateau**) |

**Robust finding:** stateless admission is embarrassingly parallel (independent per-request work) and
**clears the ≥2× bar at P=2**, scaling to ~6× at 16 cores. This holds regardless of the signature used —
independent operations always parallelize — so a stateful kernel is **not necessary** for the throughput goal.

## Council corrections folded in (what is NOT claimed)
- **Proxy bias (DeepSeek) — "stateful is counterproductive" is RETRACTED.** The uncontended serial
  section measured here is only ~1.6 µs (stateful P1 102.6 µs vs stateless 101.0 µs) — a ~1.6% fraction of
  the *fast* Ed25519 op, shrinking to <0.2% against the ~5–10× slower real ML-DSA-87. The observed P16
  *plateau* is naive-global-spinlock cache-line contention, **not** an algorithmic law, and it largely
  evaporates with a slower real signature (threads hit the lock less often). So this spike does **not**
  establish that a stateful kernel is slower — only that statelessness needs no such kernel to scale.
- **Scope (Grok) — KILL is narrow.** A stateful kernel genuinely *wins* for **global rate-limits/quotas,
  cross-request aggregates, batched/vectorized verification, shared verification caches, NUMA-sharded
  state**. KEY: those are all **cross-decision-state** features = exactly the FTO-parked territory. So they
  belong in a **separate, out-of-kernel layer**, not in-gate — which keeps *govern-the-verb* stateless and
  preserves the design-around.

## Verdict — KILL (narrow) + GRADUATE
- **KILL** the premise *"a stateful admission kernel is needed for throughput."* It is FTO-risky (parked at
  pre-screen) **and** unnecessary (stateless clears ≥2× and scales). *Not* claimed: that stateful is
  universally slower (proxy-fragile) or never useful (it helps for global policy).
- **GRADUATE:**
  1. **Engineering** — confirm the production admission path is parallel/stateless (it is stateless by
     design); horizontal scaling is the throughput lever.
  2. **R&D + counsel** — design *where* global-policy / rate-limiting / batching live as an **out-of-kernel
     stateless-to-the-kernel layer**, so those cross-decision-state features never push state in-gate; and
     commission the counsel-level SIGA claim analysis the design-around ultimately needs (Watsonx).

## Honesty caveats
Ed25519 ≠ ML-DSA-87 (size, NTT, rejection sampling differ); ~6× at "16 cores" is sub-linear (logical
cores / contention / power). No claim of competitiveness, audit, production-readiness, novelty, or
freedom-to-operate. The FTO park is engineering caution, not a legal opinion.
