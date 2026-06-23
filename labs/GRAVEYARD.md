<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion Labs — graveyard (autopsies)

## NZK-001 — naive hash-only range proof (KILLED 2026-06-23)
**Autopsy.** A hash-only (SHAKE256) range proof was built and run to test replacing the classical
ristretto255 ZK layer (the non-PQ residual). Measured **23.6× larger** than the classical proof
(330 KB vs 14 KB @ n=32) — and the classical proof it would replace is *already* zero-knowledge, which
the toy is not. **Cause of death:** hash commitments lack the additive homomorphism that makes the
classical linear-binding check (`Σ Cᵢ·2ⁱ == C`) cheap; ZK + linear-binding over hashes forces a circuit
(FRI/STARK) or algebraic (lattice) construction. The naive Σ-protocol drop-in is dead on size.
**Not buried, graduated:** the narrower question (succinct hash/STARK or lattice; optimized hash-Σ
NZK-002) went to R&D under ADR-0022/B7. Prototype kept at `spikes/nzk-001/` as the rebuild reference.
