<!--
SPDX-FileCopyrightText: 2026 TRELYAN
SPDX-License-Identifier: Apache-2.0
-->

# ADR-0027: bigint validator-stake migration (LEDGER-PRECISION-005)

**Status:** Accepted — IMPLEMENTED 2026-06-23 (council-reviewed). `Validator.stake` is now `bigint`
end-to-end; gate green (423 tests) + conformance 23/23 with no KAT/SuiteID change.

**Implementation note (council R5 hardening).** The DeepSeek/Grok/OpenAI panel flagged that replacing
the old `Number.isInteger(v.stake) && v.stake >= 0` malformed predicate with a bare `v.stake >= 0n`
DROPS the runtime type guard: in JS `aNumber >= 0n` is `true` (relational coercion), so a verifier-
supplied set carrying a runtime `number` stake (e.g. from an untrusted decode) would pass the predicate
and then THROW `bigint + number` in the accumulation — an uncontrolled crash, not the codebase's
mandated fail-closed verdict. Fix: a single audited pair of helpers in `ledger/src/sortition.ts` —
`safeStake(x)` (a non-bigint/negative value clamps to `0n`, so stake arithmetic never throws) and
`isWellFormedStakeSet(set)` (`every(v => typeof v.stake === 'bigint' && v.stake >= 0n)`, the fail-closed
predicate) — used across `chain.ts` / `leader.ts` / `sortition.ts`; `receipts/quorum.ts` inlines the
equivalent guard on its stake threshold + set. A regression test asserts a runtime non-bigint stake is
rejected (verdict `false`) WITHOUT throwing, plus a shape test covering number/float/NaN/Infinity/
string/null/undefined/object/negative-bigint. DeepSeek confirmed the fix (SHIP); Grok concurred it is
non-blocking. **Follow-up (non-blocking, Grok R5):** the guards are call-site-enforced, not
type-enforced — a branded `StakeSet` constructor that validates once at the trust boundary would make
the invariant structural rather than reliant on every consumer routing through `safeStake`. Tracked,
not required (no current consumer bypasses the guards).

## Context

`Validator.stake` is typed `number`, capping the **exactly representable** stake at
`Number.MAX_SAFE_INTEGER` (2⁵³−1). The finality and quorum arithmetic is already **BigInt-exact**
(LEDGER-PRECISION-001/002/003/004): `verifyFinalized`, `verifyViewChangeCert`, `selectLeader`, and
`verifyQuorumReceiptByStake` accumulate and compare in BigInt, and `totalStakeBig` exists. So the
**security** of finality (no float round-up across the ⅔ threshold) is handled for stakes ≤ 2⁵³.

The residual is purely at the **type layer**: a PoS deployment with wei-scale stakes (>2⁵³) cannot
represent a validator's stake exactly as a JS `number`. Widening `stake` to `bigint` removes that cap.

## Key finding — the migration is WIRE-COMPATIBLE (de-risks the change)

The validator-set binding `quorumSetId` hashes the canonical CBOR of the sorted `[pubkey, stake]`
list, and stake also appears in equivocation/vote preimages — so the worry was that `number→bigint`
changes the canonical encoding and breaks the frozen conformance KATs. **It does not.** dCBOR encodes
a JS `number` and a `bigint` of the **same integer value to identical bytes** (verified:
`encode([1,5,1000000],{dcbor:true})` === `encode([1n,5n,1000000n],{dcbor:true})` ===
`8301051a000f4240`). Therefore:

- `quorumSetId` / `setId` / vote preimages are **unchanged for every existing ≤2⁵³ stake value**.
- **`SuiteID Ps1` and `conformance/vectors/ps-*.json` are unaffected** — no KAT regeneration.
- Stakes >2⁵³ (only expressible once stake is `bigint`) encode as canonical CBOR 64-bit/bignum ints —
  a **new capability**, not a change to any existing encoding.

Conformance C-checks are live self-consistency, so they re-derive and stay green (as with ADR-0026).

## Decision (design)

Widen `stake` to `bigint` end-to-end:

- `ledger/src/types.ts` — `Validator.stake: bigint`; `EvalContext`/threshold inputs that hold stake
  (`observedAggregate`, `aggregateCap`, `perActionCeiling`?) reviewed for bigint where they denote
  stake vs. where they denote action amounts (amounts stay `number` — they are bounded).
- `ledger/src/sortition.ts` — `totalStake`/`stakeOf` return `bigint`; `totalStakeBig` collapses into
  `totalStake`; `selectLeader` drops its `BigInt(v.stake)` casts.
- `ledger/src/chain.ts`, `leader.ts` — finality + view-change drop the `BigInt(stake)` casts (stake
  is already bigint); the cross-multiply stays.
- `receipts/src/quorum.ts` — `verifyQuorumReceiptByStake` stake + `stakeThreshold` become bigint;
  drop the `Number.isInteger`/`BigInt(...)` guards in favor of bigint-native checks (`>= 0n`).
- All `ValidatorSet` literals (code + tests) — `stake: N` → `stake: Nn`. `tsc` flags every site, so
  the migration is mechanically guided.

## Consequences & risk

- **Benefit:** exact validator stakes >2⁵³ (wei-scale PoS), closing the LEDGER-PRECISION type residual
  end-to-end.
- **Risk:** broad migration — many `ValidatorSet` literals + every stake-arithmetic site. The hazard
  is **number/bigint mixing** in consensus math (a `5n + 5` throws; a missed cast skews a threshold).
  This is consensus-critical code, so it must be done as a **deliberate, council-reviewed pass with
  the full gate + conformance + property tests green**, not rushed. Because the precision *security*
  is already handled, this is a capability enhancement, not an urgent fix — sequence it accordingly.
- **No wire/KAT break** (per the finding above), so it is a Track-B change whose conformance impact is
  null for existing values.

## Recommendation

Implement on its own focused branch (the perpetual `nerion-apex-sprint` Track-B lane or a dedicated
session): flip the type, let `tsc` enumerate every site, fix mechanically, add a property test for
stakes spanning 2⁵³, run gate + conformance, council-review the consensus arithmetic, then merge.
