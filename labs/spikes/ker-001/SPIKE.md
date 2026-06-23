<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# SPIKE KER-001 — stateful vs stateless admission kernel (throughput)

- **Backlog question:** a stateful-yet-equivalent admission kernel for ≥2× throughput vs the stateless
  govern-the-verb model.
- **STEP-4 FTO PRE-SCREEN → PARK:** a stateful admission kernel = in-gate cross-decision state = SIGA
  F5 / commit-point territory the design-around avoids. The stateful framing is **parked, not built.**
- **FTO-clean reframe (what was measured):** is a stateful kernel even necessary — does stateless
  admission already clear ≑2× throughput?
- **Pre-registered threshold:** stateless ≥ 2× throughput (else the stateful case has merit).
- **Time-box:** 1 cycle.
- **FTO/crypto risk flags:** HIGH FTO sensitivity (this is the design-around's core) — handled by parking
  the risky framing; generic primitives only; no competitor-claim reading.
- **Disposition:** terminal — **KILL (narrow) + GRADUATE.** Stateless clears ≥2× (1.94× @ P=2, ~6× @ 16
  cores); "stateful is counterproductive" RETRACTED (proxy-fragile, per DeepSeek); stateful's real wins
  (global policy/batching/caching) are cross-decision-state → belong out-of-kernel (Grok). See `RESULTS.md`.
