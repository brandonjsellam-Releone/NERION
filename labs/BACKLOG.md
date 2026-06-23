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
| NZK-002 | *Optimized* hash-Σ (reduced reps + vector commitments) for offline / PQ-sig-dominated transport | ≤6× classical size at n=64 | proposed (from NZK-001 council steelman) |
| KER-001 | Stateful-yet-equivalent admission kernel vs the stateless govern-the-verb model — throughput/latency | ≥2× throughput, equivalence preserved | proposed |
| LAT-001 | Lattice (Module-LWE) range proof as the PQ disclosure path | proof ≤8 KB, verify ≤30 ms | proposed (pair with R&D ADR-0022/B7) |
