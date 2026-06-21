<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# Nerion — Apex Upgrade Program (forward track)

The Team Apex internal **audit** has converged: every component reviewed, the two richest targets
(`zkrange`, ledger consensus) deep-dived and found **sound**, 31 findings fixed/validated
([SECURITY_FINDINGS.md](SECURITY_FINDINGS.md)). This document is the **forward** track — upgrades that
build *above* the current apex, each with a council-reviewed ADR → implementation → gate → tests →
doc/ASSURANCE update. Honest sequencing by value × tractability:

| # | Upgrade | Closes / adds | Tractability |
|---|---|---|---|
| **U1** | **PQ-commitment migration** | the labeled **classical** soundness leg of the ZK layer (discrete-log → a PQ-sound binding) while keeping info-theoretic hiding | research-hard (headline) |
| **U2** | **ZK-PSR v:2 receipt wiring** | wire the audited PSP (`policyproof.ts`) + binding (`commitbind.ts`) into the signed receipt body (`commitments.psr`) — privacy-preserving compliance receipts | additive (components exist) |
| **U3** | **threshold-ML-DSA quorum** | replace the independent-signature quorum with a real PQ threshold signature (one compact signature, k-of-n) where the primitive is available | medium |
| **U4** | **LEDGER-007 cert-chain** | the ≥2/3 round-skip fairness gap — a round-0-anchored view-change cert chain | consensus change |
| **U5** | **BigInt-stake migration** | the 2⁵³ stake-sum residual (lift the bound; consensus-critical comparisons already BigInt) | mechanical/broad |
| **U6** | **Negative-oracle (#3)** | the apex-roadmap runtime negative oracle (govern-the-verb invariant) — extend | medium |
| **U7** | **Property/fuzz expansion** | broaden property + differential tests for the new surfaces | ongoing |

**Method (every item):** multi-model design consultation (DeepSeek · Grok · Hermes · …) → ADR →
implement → `npm run gate` + `npm run conformance` green → regression + property tests → update
SECURITY_FINDINGS / ASSURANCE / STATUS → commit for review. **Honesty rule unchanged:** built ≠
audited; each new construction is UNAUDITED until the external ZK/crypto audit covers it.

**Status:** U1 design consultation in progress (2026-06-21).
</content>
