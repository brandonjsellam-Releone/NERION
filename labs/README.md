<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# `labs/` — Nerion Labs (Innovation team sandbox)

The hermetically isolated home of the **Innovation team** (`nerion-innovation-daily`; charter in
[../docs/APEX_TEAMS.md](../docs/APEX_TEAMS.md) §5). It holds **throwaway, disposable prototypes** that
empirically benchmark whether a *different* architecture could obsolete a **core** Nerion assumption.

**Invariants (CI-enforced by `tools/labs-isolation-check.mjs`):**
- `labs/` imports **nothing** from repo prod source (`crypto/ kernel/ ledger/ keystore/ …`). Mocks/toys only.
- No change on an `innovation/*` branch touches a frozen asset (SuiteID `Ps1`, `conformance/`, `vectors/`, `ps-*.json`, any KAT).
- `labs/` is excluded from the production gate/conformance/build/package. Every artifact here is deletable with **zero** protocol impact.
- Output is **measured numbers + a KILL/GRADUATE verdict**, never a design doc, never prod code, never a legal/novelty claim.

**Layout:** `BACKLOG.md` (architectural bets) · `SPIKES.md` (state table) · `INNOVATION_LOG.md`
(append-only) · `GRAVEYARD.md` (autopsies) · `spikes/<id>/` (SPIKE.md + prototype + RESULTS.md) ·
`tools/` (the sandbox guards) · `_graveyard/` (dead code, retained as disposable reference).
