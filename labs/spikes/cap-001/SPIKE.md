<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# SPIKE CAP-001 — HMAC-chain (Macaroon) vs signature-chain capabilities

- **Falsifiable question:** does a Macaroon-style HMAC-chained capability add offline attenuation/delegation
  Nerion's permit model lacks, at acceptable cost, while staying PQ?
- **Premise corrected (intake `capabilities/src/capability.ts`):** Nerion ALREADY has offline-attenuable
  delegation via ML-DSA-87 signature-chains. Real question = the signature-chain vs HMAC-chain tradeoff.
- **Time-box:** 1 cycle.
- **FTO/crypto risk flags:** FTO-clean (capability tokens; no SIGA overlap); node:crypto only.
- **Disposition:** terminal — **NO KILL (sig-chain is the safe default) + GRADUATE a real hybrid.** Macaroon
  is tiny+fast but shared-secret (no public/decentralized verification — council-confirmed). Council surfaced
  a measured upside: a **signed-root + HMAC-caveat hybrid** keeps public verifiability AND is 3.9–14.6×
  smaller at depth ≥3–4. See `RESULTS.md`.
