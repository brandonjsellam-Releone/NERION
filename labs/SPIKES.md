<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion Labs — spike state table

| Spike | Opened | State | Measured result | Verdict | Handoff |
|-------|--------|-------|-----------------|---------|---------|
| [NZK-001](spikes/nzk-001/RESULTS.md) | 2026-06-23 | TERMINAL | hash-only range proof 23.6× larger than classical (330 KB vs 14 KB @ n=32); honest verifies, tamper rejected | **KILL** (unoptimized drop-in) **+ GRADUATE** | R&D: FRI/STARK or lattice (ADR-0022/B7); NZK-002 hedge |
| [NZK-002](spikes/nzk-002/RESULTS.md) | 2026-06-23 | TERMINAL | GGM all-but-one tree real+verified (N=256/4096, tamper caught); modeled MPCitH size ~1.1–1.9× classical at a 100ms–1s prover budget (~25–30× smaller than NZK-001 naive) | **GRADUATE** (qualified; not a competitiveness claim) | R&D: PQ-disclosure bake-off MPCitH vs STARK vs lattice (ADR-0022/B7) |
| [KER-001](spikes/ker-001/RESULTS.md) | 2026-06-23 | TERMINAL | FTO-PARKED stateful-kernel framing (SIGA in-gate-state); measured stateless admission scales 1.94× @P=2 → 6× @16 cores (clears ≥2×) | **KILL** (narrow: stateful kernel not needed for throughput) **+ GRADUATE** | Eng: confirm stateless-parallel path; R&D+counsel: out-of-kernel policy layer + SIGA claim analysis |
| [LED-001](spikes/led-001/RESULTS.md) | 2026-06-23 | TERMINAL | independent-sig finality cert is linear (k=256 → ~1.16 MB, 256 verifies); Merkle no help (measured); STARK-agg crossover k≈10 (model) | **NO KILL** — status quo sound; **CONDITIONAL GRADUATE** | R&D: STARK-agg (prover-budget + fail-open) / threshold-lattice (DKG) only IF large-set+light-client regime |
| [VRF-001](spikes/vrf-001/RESULTS.md) | 2026-06-23 | TERMINAL | raw PQ hash-beacon sortition grindable (512 tries → 98% target install; proposer ≫); EC-VRF private+grind-resistant but classical | **INCONCLUSIVE → REOPEN (VRF-002)** | R&D: build quorum-seed + PQ-VDF sortition; settle whether private leader election is required (ADR-0004) |

> Single-active-spike rule: at most one non-terminal spike at a time. NZK-001, NZK-002, KER-001, LED-001, VRF-001 are terminal.
> **LED-001 lesson:** the council reversed an over-eager KILL — quantify the gap, but weigh it against the status quo's minimal-TCB / fail-closed virtues before recommending a replacement.
