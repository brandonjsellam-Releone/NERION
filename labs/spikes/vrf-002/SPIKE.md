<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# SPIKE VRF-002 — quorum-seed + sloth-VDF sortition (VRF-001 reopen)

- **Falsifiable question:** does a quorum-seed + PQ-VDF beacon recover grind-resistance/unpredictability
  while staying post-quantum, closing the gap the raw hash-beacon (VRF-001) left open?
- **Core assumption attacked:** that leader unpredictability needs the classical EC-VRF.
- **Time-box:** 1 cycle.
- **FTO/crypto risk flags:** FTO-clean (VDF/sortition; no SIGA overlap); node:crypto only.
- **Disposition:** terminal — **GRADUATE; closes VRF-001 as: NO free PQ replacement.** Built a real sloth
  VDF (verifies, asymmetry ~170–235×, proof 63–250 B). Council corrected the grind-resistance to a
  *conditional, brittle* deadline-barrier (realistic edge ~94×, not 38k; last-revealer/withholding attacks);
  the VDF adds a liveness floor + linear verify + public (non-private) sortition. EC-VRF pragmatic hybrid
  (ADR-0004) vindicated. See `RESULTS.md`.
