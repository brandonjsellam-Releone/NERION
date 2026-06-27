<!-- SPDX-FileCopyrightText: 2026 TRELYAN -->
<!-- SPDX-License-Identifier: Apache-2.0 -->

# Nerion formal models (TLA⁺)

A small, TLC-checkable model of Nerion's stake-finality consensus core. It exists
to **find counterexamples** to the safety properties the implementation relies on
— not to certify the implementation.

## What's here

- **`NerionConsensus.tla`** — models stake-weighted finality + accountable safety,
  faithful to `ledger/src/equivocation.ts` and `governance/src/quorum.ts`.
  Configs: `NerionConsensus.cfg` (4 val / 2 Byz), `_6v1b.cfg`, `_7v2b.cfg`.
- **`NerionViewChange.tla`** — models the round / view-change layer and
  machine-checks `docs/CONSENSUS-CAVEATS.md` §1: a ≥2/3 coalition can **skip rounds
  cheaply** (LEDGER-007) and control which block is *proposed*, but that is a
  **fairness-only** weakness — `SafetyUnderRoundSkip` and `HonestAgreementUnderSkip`
  show round manipulation cannot manufacture a fork (finalization still needs a >2/3
  quorum). Machine-checked: **no error** over 708 states (4 val / 2 Byz) and 564
  states (4 val / 1 Byz). Configs: `NerionViewChange.cfg`, `NerionViewChange_1byz.cfg`.
  Both models run in CI (`.github/workflows/ci-formal.yml`).

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

**Machine-checked result (TLC v1.8.0, 2026-06-26):** `Model checking completed. No error
has been found.` — all five invariants (`TypeOK`, `NoHonestEquivocation`,
`AccountableSafety`, `HonestAgreement`, `QuorumIntegrity`) hold over the **144 distinct
reachable states** of the default configuration (4 validators, 2 Byzantine, 1 height, 2
blocks); state-graph depth 7; runs in <1 s.

**Verified across multiple configurations** (CI runs all three):

| Config | Validators / Byzantine | Byzantine ratio | Distinct states | Exercises |
|---|---|---|---|---|
| `NerionConsensus.cfg` | 4 / 2 | 50% (>⅓) | 144 | `AccountableSafety` non-vacuous |
| `NerionConsensus_6v1b.cfg` | 6 / 1 | 16.7% (<⅓) | 972 | `HonestAgreement` non-vacuous |
| `NerionConsensus_7v2b.cfg` | 7 / 2 | 28.6% (<⅓) | 3 888 | `HonestAgreement` near the ⅓ boundary |

All three report *no error*, spanning honest-supermajority (agreement holds) through
Byzantine-majority (accountable slashing). The model is intentionally small; widen
`Validators`, `Heights`, `Blocks`, or override `Stake` with a non-uniform function to
explore stake-weighted cases.

A terminal-stutter (`Next == NormalNext \/ (~ENABLED NormalNext /\ UNCHANGED vars)`) makes
the legitimately-terminating behaviour deadlock-free, so TLC runs with **no special flags**
and genuine deadlocks elsewhere are still caught.

> **Honesty note (scope of the claim).** This is **machine-checked model checking of an
> abstraction**, run both locally and in CI (`.github/workflows/ci-formal.yml` runs TLC on
> every change to `docs/formal/`). It establishes that the modelled invariants hold over the
> model's finite state space — it is **not** a proof of the TypeScript/Rust implementation,
> and it abstracts away signatures, networking, timing, and view-change. "Model-checked" is a
> strong, specific claim; "implementation-proven" it is not.
>
> **Model ↔ implementation bridge.** To connect the abstraction to the real code, the same three
> invariants (`NoHonestEquivocation`, detection-soundness, `AccountableSafety`) are **property-tested
> against the actual `ledger/src/equivocation.ts`** over a randomized space of validator sets and
> honest/Byzantine attestation patterns — see `ledger/test/equivocation.property.test.ts`. So the
> property is both model-checked (abstract) and property-checked (concrete), though still not a formal
> proof of the implementation.
