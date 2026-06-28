# CF-5 — metamorphic finality oracle (single-implementation arm)

> Status: research-engineering. UNAUDITED, pre-FTO. Additive — **tests only**, `verifyFinalized` is
> unchanged. No wire / KAT / `Ps1` change, no cross-decision state. Branch-only.

## What

`crypto`-grade light-client finality (`verifyFinalized`) is the function a node trusts to decide a
block is final from `block + attestations + validator set` alone. CF-5 pins the **metamorphic
relations** its verdict must satisfy over its attestation input, against the shipped function
(`ledger/test/finality-metamorphic.property.test.ts`, fast-check, fixed seeds):

- **Duplicate-idempotence** — repeating attestations never inflates attesting stake (dedup by
  validator). This is the **no-double-count safety property** (and turns a prior "does it dedup?"
  question into a permanent regression guard — it does, via a `counted` set).
- **Order-independence** (valid input) — permuting an all-valid attestation set leaves the verdict
  (`attestingStake`, `finalized`) unchanged.
- **Junk-invariance** — wrong-block / wrong-height / wrong-suite / non-staked attestations are ignored.
- **Monotonicity** — a superset of valid attestations never yields less attesting stake than a subset.

## The one intentional order-dependence (documented, not a defect)

`verifyFinalized` caps PQ verifies at **one per validator** (DOS-VERIFY-001), so a garbage-signature
attestation placed *before* a validator's valid one spends that validator's single verify slot and
drops it. The test pins this precisely and shows it is **liveness-only**: with a minimal 2-of-3 quorum
(34+33 = 67), garbage-first yields 33/100 (not finalized) while valid-first yields 67/100 (finalized) —
the ordering can only **lower** counted stake, **never forge** a higher one (safety preserved). In
production the gossip ingress filter verifies attestation signatures before pooling, so unfiltered
mixed-validity input is a standalone-light-client concern, not the consensus path.

## Why it is beyond the prior bar

Existing tests check specific finality scenarios; none assert the metamorphic invariants
(dedup-idempotence, permutation-invariance, junk-invariance, monotonicity) that a correct finality
verifier must hold for *all* inputs. The benchmark framing is a count of checked relations, not a
proof.

## Scope / honesty

- **Single-implementation** metamorphic testing only. The cross-implementation differential arm (TS
  vs the Rust ledger) is out of scope — there is no Rust ledger yet (gated on backlog A29).
- The suite checks the finality **decision** (`attestingStake` / `finalized`), not the verify
  **cost** — it does not count PQ verifications (that would need to instrument the internal
  `safeVerify`). The CPU-DoS defense is DOS-VERIFY-001's one-verify-per-validator cap (documented
  above), not something asserted here. Boundary cases (the exact 2/3 floor, an empty/zero-stake set
  failing closed) are covered; broader fixtures (extreme stake weights) are a cheap future extension.
- Tests only; `verifyFinalized` is unchanged. The DOS-VERIFY-001 order-dependence is a documented,
  safety-preserving CPU-DoS tradeoff, not a bug. UNAUDITED / pre-FTO.

*Origin: Beyond-Apex Frontier item CF-5 (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)).*
