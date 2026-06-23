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
