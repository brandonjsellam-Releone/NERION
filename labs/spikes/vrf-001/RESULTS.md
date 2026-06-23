<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# VRF-001 — RESULTS (raw hash-beacon measured-grindable; the real PQ contender is untested → REOPEN)

> **TOY / MOCK — UNAUDITED, pre-FTO.** No novelty/non-infringement claim. © TRELYAN.
> The verdict was **downgraded from "NO KILL / classical justified" to INCONCLUSIVE** after council review.

## Question
Leader sortition uses a **classical ECVRF-EDWARDS25519** (`ledger/src/vrf.ts`) — the code already
discloses this as a deliberate liveness/fairness residual ("no standardized PQ VRF exists", ADR-0004), so
"the VRF is classical" is a non-finding. Real question: **can a PQ sortition replace it, and what does
going PQ cost?**

## Measured (raw PQ hash-beacon sortition; node:crypto only)
- Hash-beacon (leader = stake-weighted argmin over `H(beacon‖validator)`): **PQ**, **0-byte proof**
  (publicly recomputable), select <1 ms, deterministic public verify ✓.
- EC-VRF reference: ~80 B proof, ~96 µs verify (Ed25519 proxy), **classical**, **private + unpredictable**.
- **Grinding (target p=1/128):** beacon tries T → P(install target leader), measured ≈ 1−(1−p)^T:

  | T | 1 | 8 | 64 | 512 |
  |---|---|---|---|---|
  | P(install) | 0.008 | 0.056 | 0.404 | **0.984** |

## Council corrections (both seats — my verdict was wrong)
- **DeepSeek — the quorum-beacon mitigation is RETRACTED.** A *proposer* grinds the block hash *before*
  proposing (reorder/insert txns, tweak nonce/extra-data) at millions of hashes/slot. Post-finalization
  "no single party controls the hash" does **not** stop pre-proposal grinding. The measured curve already
  saturates by T=512 (98%); a proposer's achievable T (≫2²⁰) ⇒ **≈100%** target install. So a raw public
  hash-beacon is grindable **even with** a quorum-finalized hash. Leader prediction also enables targeted
  DoS/censorship/bribery — must be explicitly accepted, not hand-waved.
- **Grok — the option space was INCOMPLETE.** I only measured the *naive* hash-beacon. The real PQ
  contender is a **quorum-finalized seed + (PQ) VDF delay** (output revealed only after the election window
  closes; grinding then requires breaking the quorum threshold OR parallelizing the VDF — far stronger than
  "512 hash tries"), or a **PQ threshold randomness beacon** (drand-style; the only gap is a production PQ
  threshold-sig library, not a fundamental primitive). I did **not** measure these. Also: whether *private*
  leader election is load-bearing for Nerion is unexamined — a public-but-unbiasable beacon may be strictly
  better (auditable, removes the VRF-secret-key SPOF) **and** PQ.

## Verdict — INCONCLUSIVE; REOPEN (not the NO-KILL I first proposed)
- **Established (measured):** a *raw* public hash-beacon is PQ + cheap but **grindable** (fatal as-is), and
  the EC-VRF buys grind-resistance + privacy.
- **NOT established:** that the classical VRF is "permanently justified." The real PQ contender — a
  quorum-seed + PQ-VDF (or PQ threshold beacon) that **preserves grind-resistance while being PQ** — was not
  built or measured here. My initial NO-KILL over-reached.
- **GRADUATE → R&D (sharper questions), reopen as VRF-002:**
  1. Build/spec a **quorum-finalized-seed + PQ-VDF sortition** and measure latency + grind-resistance + cost
     — does it recover unpredictability without the classical primitive?
  2. From the **threat model (ADR-0004)**: is *private* (vs merely unbiasable-public) leader election
     actually required? If yes and no PQ VRF exists, the classical hybrid stays (disclosed residual). If no,
     a PQ VDF-beacon may eliminate the classical primitive entirely.
- The honest interim: the classical EC-VRF remains the pragmatic choice **for now** (per ADR-0004), but the
  PQ path is plausibly a **VDF/threshold beacon**, not merely "wait for a standardized PQ VRF."

## Honesty caveats
Only the raw hash-beacon + its grindability were executed/measured; the VDF/quorum/threshold contenders are
unbuilt (that's VRF-002). EC-VRF verify time is an Ed25519 proxy. No competitiveness/audit/novelty/FTO claim.
