<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# VRF-002 — RESULTS (VDF-beacon is real but NOT a clean PQ win; closes the VRF-001 reopen)

> **TOY / MOCK — UNAUDITED, pre-FTO.** No novelty/non-infringement claim. © TRELYAN.
> The grind-resistance framing was **corrected by council review** (my draft over-claimed).

## Question (the VRF-001 reopen)
VRF-001 left it open whether a **quorum-seed + PQ-VDF** sortition recovers grind-resistance while staying
post-quantum. This builds a real **sloth VDF** (a sequential chain of modular square roots mod a 256-bit
p≡3 mod 4 — PQ-safe because its delay rests on **sequentiality**, not factoring/DL, and Grover gives no
speedup on inherently-sequential iteration) and measures it.

## Measured (sloth VDF; node:crypto only; verifies + tamper-rejected)
| T | eval | verify | asymmetry | proof |
|---|---|---|---|---|
| 500 | ~90 ms | ~0.5 ms | ~170× | 63 B |
| 2000 | ~330 ms | ~1.4 ms | ~235× | 250 B |

The eval/verify asymmetry and small proof are real and the chain verifies (and rejects a 1-bit tamper).

## The grind-resistance framing — corrected by council
My draft claimed a "38,766× slowdown → recovers grind-resistance." **Both seats corrected it:**
- **Right mechanism (DeepSeek) = a deadline-barrier, NOT a compute multiplier.** A grinder must learn a
  candidate seed's VDF *output* (the leader) *before* committing that seed at finalization. The per-machine
  "38,766×" is the *naive sequential* view; a **parallel** adversary computes 512 candidates in ~1 eval, so
  the realistic edge is only **~94×** (measured) — and even that holds *only if* `VDF_delay > the
  seed-commit decision window`, calibrated against the **global-fastest** adversary (cloud/ASIC rental), not
  reference hardware. I never specified that window; as drawn it may give far less than implied.
- **The barrier is BRITTLE (Grok).** Residual attacks: **last-revealer head-start** (the final quorum signer
  starts the VDF first), **withholding + selective reveal** (a signer evaluates candidates on the partial
  seed, releases its signature only for a favorable leader), **precomputation** on predictable seed
  components, and **ASIC/rental** beating the calibrated delay.

## Honest costs (measured / stated)
- **Weak VDF:** verify is O(T) (linear, not succinct) — and widening the deadline-barrier (larger T) grows
  verify too. Succinct PQ VDFs (O(log T)) do not exist (Wesolowski/Pietrzak need classical unknown-order groups).
- **Hard liveness floor** = the VDF delay (must exceed the decision window).
- **No private sortition:** the leader is **public** once the VDF completes — it recovers *unpredictability*,
  not Algorand-style *privacy*.

## Verdict — closes VRF-001: NO free PQ replacement; EC-VRF pragmatic hybrid is JUSTIFIED
Across VRF-001 + VRF-002 the PQ leader-election option space is now mapped and measured:
- classical EC-VRF — private + succinct, but classical (disclosed residual, ADR-0004);
- raw hash-beacon — PQ but **grindable** (VRF-001: 512 tries → 98%);
- sloth-VDF beacon — PQ + unpredictable, but **conditional/brittle** grind-resistance (deadline calibration +
  last-revealer/withholding attacks), a **liveness floor**, **linear verify**, and **public** (non-private) sortition;
- true PQ VRF — **does not exist** yet.

**Every PQ option carries a real cost; none is a free replacement.** The VDF-beacon's concrete gain over the
EC-VRF is **PQ-safety + no secret-key SPOF**, *not* clean grind-resistance — so the EC-VRF stays competitive,
and the code's pragmatic-hybrid choice (classical VRF for liveness/fairness; PQ ML-DSA-87 for safety) is
**vindicated**, not an oversight.

**GRADUATE → R&D (the now-sharpened open question):** PQ leader-election remains open. If pursued, a
VDF-beacon needs (a) a rigorous `delay > decision-window` calibration vs the global-fastest adversary, (b)
last-revealer/withholding mitigation, (c) acceptance of public sortition + the liveness floor. Near-term
honest posture: safety is already PQ; the VRF residual is a bounded, documented liveness/fairness risk — keep
the EC-VRF.

## Honesty caveats
The sloth VDF + its asymmetry are real and measured; the grinding/security analysis is analytic (decision
window, adversary hardware, and the residual attacks are not simulated). EC-VRF figures are reference values.
No competitiveness/audit/novelty/FTO claim.
