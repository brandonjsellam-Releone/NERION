<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion Labs — architectural-bet backlog

Read-only intake from R&D's `docs/FRONTIER.md` *research-bet / speculative* tiers + maintainer-seeded
bets. Each entry must satisfy the two-part conjunction (executes disposable code **and** tests whether a
*different* architecture replaces a *core* assumption). No independent SOTA scout here — field-scouting
stays in R&D.

| ID | Bet (core assumption it attacks) | Falsifiable threshold | State |
|----|----------------------------------|-----------------------|-------|
| **NZK-001** | Hash-only (PQ) range proof replaces the classical ristretto255 ZK layer | proof ≤2 KB, prove ≤100 ms, verify ≤50 ms | **DONE → KILL+GRADUATE** |
| NZK-002 | *Optimized* hash-Σ (MPCitH/GGM all-but-one tree) for offline / PQ-sig-dominated transport | ≤6× classical size at n=64 | **DONE → GRADUATE** (modeled ~1.1–1.9× under a prover budget; threshold met but comparator caveat — bake-off vs Bulletproofs/STARK/lattice) |
| NZK-003 | PQ-disclosure **bake-off**: MPCitH vs STARK vs lattice, full impl, measured size×prover×verifier ms | beat Bulletproof-class size at ≤1 s prover, PQ-sound | proposed (NZK-002 handoff → R&D, ADR-0022/B7) |
| KER-001 | Stateful-yet-equivalent admission kernel vs the stateless govern-the-verb model — throughput/latency | ≥2× throughput, equivalence preserved | **DONE → FTO-PARKED + KILL (narrow) + GRADUATE** (stateless clears ≥2×; stateful framing = SIGA in-gate-state, parked; global-policy state → out-of-kernel layer) |
| LAT-001 | Lattice (Module-LWE) range proof as the PQ disclosure path | proof ≤8 KB, verify ≤30 ms | proposed (pair with R&D ADR-0022/B7) |
| LED-001 | Aggregated finality cert (STARK-of-sigs / threshold-lattice) vs k independent ML-DSA-87 sigs | smaller AND fail-closed/PQ/minimal-TCB | **DONE → NO KILL (status quo sound) + CONDITIONAL GRADUATE** (linear gap real but only bites large-set+light-client; alternatives hide prover-time/fail-open/DKG costs) |
| LED-002 | (R&D) STARK-aggregated finality under a hard prover-time budget + fail-open analysis | succinct AND meets block-finality prover budget | proposed (LED-001 conditional handoff → R&D) |
| VRF-001 | PQ sortition vs classical ECVRF leader election | PQ AND grind-resistant AND ≤ EC-VRF cost | **DONE → INCONCLUSIVE / REOPEN** (raw hash-beacon grindable; real PQ contender = quorum-seed+VDF untested) |
| VRF-002 | Quorum-finalized-seed + PQ-VDF (or PQ threshold beacon) sortition | grind-resistant + PQ at acceptable latency | **DONE → GRADUATE** (real sloth VDF; grind-resistance conditional/brittle; liveness floor + public sortition; closes VRF-001 — no free PQ replacement, EC-VRF hybrid vindicated) |
| CAP-001 | HMAC-chain (Macaroon) vs ML-DSA signature-chain capabilities | offline attenuation + small + publicly verifiable | **DONE → NO KILL + GRADUATE HYBRID** (Macaroon shared-secret-only; signed-root+HMAC hybrid keeps public verify AND is 3.9–14.6× smaller at depth ≥3–4) |
| CAP-002 | (R&D) signed-root + HMAC-caveat hybrid capability for deep delegation | public-verifiable + small + first-party caveats sound | proposed (CAP-001 hybrid handoff → R&D) |
| **REV-001** | Sparse-Merkle revocation accumulator — constant-size (1024 B) non-membership proofs to replace notAfter-only revocation | proof size acceptable + freshness model specified + short-TTL threat-model comparison done | **DONE → KILL (underspecified)** (primitive numbers good: revoke 0.1ms, verify 0.069ms, 1024 B; but capIndex collision = architectural defect; root-distribution unspecified; short-TTL comparison never done — council: "SMT converts key compromise into a freshness attack on the revocation surface") |
| REV-002 | SMT revocation with collision-resistant capIndex + specified root-distribution design | all three REV-001 gaps resolved + corrected scaling table | blocked on R&D (design doc: root-distribution model + short-TTL threat analysis required before lab re-entry) |
