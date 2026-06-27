<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# SPIKE NZK-001 — hash-only PQ range proof (proof-elimination)

- **Falsifiable question:** can a hash-only (SHAKE256, post-quantum) range proof replace the classical
  ristretto255 ZK range proof (`disclosure/src/zkrange.ts`) at competitive size/speed?
- **Contradicted core assumption:** that the disclosure layer's privacy must rest on a classical
  (non-PQ) prime-order group. (Two-part conjunction satisfied: MODE = executes disposable code;
  TARGET = a *different* trust substrate for a *core* assumption.)
- **Pre-registered KILL thresholds:** proof ≤ 2 KB AND prover ≤ 100 ms AND verifier ≤ 50 ms.
- **Time-box:** 1 cycle (single-session spike).
- **FTO/crypto risk flags:** generic public-domain primitives only (hashing, Merkle, cut-and-choose,
  Fiat–Shamir); no competitor-claim reading; govern-the-verb unaffected (disclosure-layer only).
- **Disposition:** terminal — **KILL (qualified) + GRADUATE** (see `RESULTS.md`). Prototype retained
  in place as the rebuild reference for the graduated handoff.
