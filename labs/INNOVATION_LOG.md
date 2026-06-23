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
