<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# SPIKE NZK-002 — optimized hash-only (MPCitH/GGM) range proof

- **Falsifiable question:** does an optimized hash-only range proof (fewer reps + a GGM all-but-one seed
  tree — the Picnic/MPC-in-the-head technique) overturn NZK-001's naive 23.6× and reach ~4–6× classical?
- **Origin:** the NZK-001 council steelman (Grok). Reopens NZK-001's graduated question with a *different*
  hash-only architecture (still attacks the same core assumption: the non-PQ classical ZK substrate).
- **Pre-registered threshold:** ≤ 6× classical size at n=64.
- **Time-box:** 1 cycle.
- **FTO/crypto risk flags:** generic public-domain primitives (GGM puncturable PRF, Merkle, Fiat–Shamir,
  MPCitH); no competitor-claim reading; disclosure-layer only.
- **Disposition:** terminal — **GRADUATE (qualified)**. Threshold met *under a prover-time budget*
  (~1.1–1.9× modeled), but with a comparator caveat (the right targets are Bulletproofs + STARK/lattice,
  not the weak linear classical baseline). See `RESULTS.md`.
