# CF-2 — accountable-safety slashable-evidence extractor

> Status: research-engineering. UNAUDITED, pre-FTO. Additive consensus-layer artifact — no
> governance / govern-the-verb surface, no in-gate cross-decision state, no wire / KAT / `Ps1`
> change. Strictly MORE evidence (never relaxes a check). Branch-only.

## Theorem (accountable safety)

For a validator set of total stake `T`, if two **distinct** blocks at the **same height** both
finalize — each attested by `≥ ⌈2T/3⌉` stake — then the two attesting sets intersect in
`≥ ⌈T/3⌉` stake, and every validator in that intersection signed two conflicting attestations at one
height, i.e. is **slashable**.

*Proof.* `|A ∩ B| ≥ |A| + |B| − T ≥ 2⌈2T/3⌉ − T ≥ ⌈T/3⌉`. ∎

Casper/Gasper accountable safety is normally a paper theorem plus an ad-hoc slashing script; the
`≥ 1/3` culpability is asserted, not extracted as a first-class artifact with a published
stake-coverage number.

## What

`ledger/src/accountable.ts` adds `extractSlashableSet(a, b, set)` → `AccountableSafetyReport`. Given
two `FinalizedBlock` verdicts at one height it:

1. confirms a genuine conflict (distinct hashes, same height, both finalized; recomputes each header
   hash so a mislabeled `hash` is caught),
2. extracts the **cryptographically-verified** double-signers (reuses `detectEquivocations` +
   `verifyEquivocationProof`, so every counted validator has two verified same-height attestations on
   the two distinct blocks — no honest cross-height validator can be slashed, LEDGER-EQUIV-001),
3. sums their **BigInt** stake (ADR-0027 exact stake), and
4. checks `culpableStake ≥ ⌈T/3⌉` — the theorem's floor, **computed and reported**, not assumed.

The test builds two `≥ 2/3` quorums (`v1+v2` and `v1+v3` over stakes 34/33/33) overlapping in exactly
`v1` (34 = ⌈100/3⌉), and asserts the extractor returns `v1` as the sole slashable validator with
`culpableStake = 34`, `meetsOneThird = true`. Negatives: identical blocks, non-finalized inputs,
different heights, and — importantly — a **bogus "finalized" pair** whose overlap is below the floor
is flagged (`meetsOneThird = false` + reason), so the extractor does not blindly trust the `finalized`
flag.

## Why it is beyond the prior bar

`detectEquivocations` already finds double-signers on given inputs; what was missing is the
first-class **accountable-safety report** that ties two finalized verdicts to a verified slashable set
**with a proven `≥ 1/3` stake-coverage number**. Comparable PoS clients publish no such completeness
figure. Benchmark framing: a MEASURED stake-coverage number over constructed conflicts, **not** a
machine-checked proof of the theorem.

## Scope / honesty

- Additive; the ledger's append/finality path is unchanged. The `finalized` precondition on each input
  is the caller's (obtained from the light-client finality verifier `verifyFinalized`); the extractor
  independently verifies the equivocation signatures and the `≥ 1/3` coverage, and flags a pair whose
  overlap falls short rather than trusting the flag.
- **Caller preconditions** (council note): `set` MUST be the active validator set at the blocks'
  height — the extractor cannot cross-check this, and a wrong set yields a wrong `totalStake`/threshold;
  `finalized` MUST come from `verifyFinalized` (≥ 2/3 verified attesting stake). Deduplication is by
  validator pubkey — distinct keys are distinct validators, which only strengthens the ≥ 1/3 bound.
- The theorem is stated as an argument (above) and exercised by a measured test; it is **not** a
  machine-checked proof (that would need a prover toolchain — see GOV-NI-PROOF / SAF-1, toolchain-gated).
- Consensus-layer only; govern-the-verb is untouched. UNAUDITED / pre-FTO.

*Origin: Beyond-Apex Frontier item CF-2 (see [BEYOND_APEX_FRONTIER.md](./BEYOND_APEX_FRONTIER.md)).*
