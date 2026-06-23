<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# SPIKE VRF-001 — PQ sortition vs classical ECVRF leader election

- **Falsifiable question:** can a PQ sortition replace the classical ECVRF-EDWARDS25519 leader election,
  and what does going PQ cost?
- **Core assumption attacked:** that leader unpredictability must rest on a classical (EC) VRF.
- **Time-box:** 1 cycle.
- **FTO/crypto risk flags:** FTO-clean (randomness/sortition; no SIGA overlap); read-only intake of `vrf.ts`.
- **Disposition:** terminal — **INCONCLUSIVE → REOPEN as VRF-002.** Measured: a raw public hash-beacon is
  PQ + cheap but grindable (512 tries → 98% target install; proposer ≫ that). Council showed the real PQ
  contender (quorum-seed + PQ-VDF, or PQ threshold beacon) was untested, so the initial NO-KILL over-reached.
  See `RESULTS.md`.
