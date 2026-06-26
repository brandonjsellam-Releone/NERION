<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion formal models (TLA⁺)

A small, TLC-checkable model of Nerion's stake-finality consensus core. It exists
to **find counterexamples** to the safety properties the implementation relies on
— not to certify the implementation.

## What's here

- **`NerionConsensus.tla`** — models stake-weighted finality + accountable safety,
  faithful to `ledger/src/equivocation.ts` and `governance/src/quorum.ts`.
- **`NerionConsensus.cfg`** — a small finite configuration (4 validators).

## What is modelled

| Concept | In the model | In the code |
|---|---|---|
| Finality threshold | `3·stake(attestors) > 2·total` | `≥2/3` accountable finality (equivocation.ts) |
| Equivocation | attesting two distinct blocks at one height | `detectEquivocations` / `verifyEquivocationProof` same-height rule |
| Honest behaviour | ≤ one block per height | honest validators attest once per height |
| Byzantine behaviour | may attest any blocks (equivocate) | the adversary the slashing guards defend against |

### Invariants checked

- **`AccountableSafety`** — two distinct blocks finalized at one height ⇒ ≥1/3
  stake equivocated (and is slashable). The Casper-style headline property.
- **`HonestAgreement`** — with <1/3 Byzantine stake, no two distinct blocks
  finalize at one height.
- **`NoHonestEquivocation`** — honest validators are never slashable
  (models the LEDGER-EQUIV-001 cross-height guard).
- **`QuorumIntegrity`** — a finalized block always carries a >2/3 stake quorum.

## What is abstracted away (and therefore NOT verified here)

Signatures and their forgery resistance; networking, message loss, and ordering;
wall-clock timing and the validity-window guards; **view-change / round-skip**
(tracked separately in `docs/adr/ADR-0018`); the governance M-of-N independent-
signature quorum (modelled here only as the stake-finality analogue). This model
checks the *agreement/accountability* layer, nothing else.

## Running it

Install the [TLA⁺ tools](https://github.com/tlaplus/tlaplus) (Java + `tla2tools.jar`):

```bash
# from this directory
java -cp /path/to/tla2tools.jar tlc2.TLC -config NerionConsensus.cfg NerionConsensus.tla
```

Expected: all invariants hold for the default configuration (no counterexample).
The model is intentionally tiny so it checks in seconds; widen `Validators`,
`Heights`, `Blocks`, or override `Stake` with a non-uniform function to explore
stake-weighted cases.

> **Honesty note.** These artifacts were authored to be TLC-runnable but were
> **not** executed by TLC in this repository's CI (no Java/TLA⁺ toolchain is
> provisioned here yet). Treat them as a reviewable, runnable specification, not
> as machine-checked-in-CI evidence — wiring TLC into CI is a follow-up.
