<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion Labs — spike state table

| Spike | Opened | State | Measured result | Verdict | Handoff |
|-------|--------|-------|-----------------|---------|---------|
| [NZK-001](spikes/nzk-001/RESULTS.md) | 2026-06-23 | TERMINAL | hash-only range proof 23.6× larger than classical (330 KB vs 14 KB @ n=32); honest verifies, tamper rejected | **KILL** (unoptimized drop-in) **+ GRADUATE** | R&D: FRI/STARK or lattice (ADR-0022/B7); NZK-002 hedge |

> Single-active-spike rule: at most one non-terminal spike at a time. NZK-001 is terminal.
