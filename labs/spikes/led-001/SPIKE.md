<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# SPIKE LED-001 — finality-certificate scaling (independent sigs vs aggregation)

- **Falsifiable question:** does Nerion's k-independent-ML-DSA-87 finality cert scale with validator-set
  size, or does a PQ-sound aggregation (STARK-of-sigs / threshold-lattice) obsolete it above some k?
- **Core assumption attacked:** that a flat quorum-of-signatures finality cert is the right structure
  (deliberately chosen in `receipts/src/quorum.ts` to stay PQ — threshold sigs were deemed classical).
- **Pre-registered threshold:** an aggregation that is smaller AND keeps fail-closed/PQ/minimal-TCB.
- **Time-box:** 1 cycle.
- **FTO/crypto risk flags:** FTO-clean (signature aggregation; no SIGA perception/commit-point overlap);
  generic primitives; read-only intake of `quorum.ts`.
- **Disposition:** terminal — **status quo SOUND (no KILL); CONDITIONAL GRADUATE.** Measured the linear
  curve + crossover k≈10 (model), but council showed the alternatives hide prover-time/fail-open/DKG costs;
  independent sigs stay the right default outside a large-set + light-client + high-frequency regime. See `RESULTS.md`.
