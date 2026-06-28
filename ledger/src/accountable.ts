// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CF-2 — accountable-safety slashable-evidence extractor.
 *
 * Casper-style accountable safety: if two conflicting blocks at the SAME height both finalize (each
 * with >= 2/3 stake), the two quorums must intersect in >= 1/3 of total stake, and every validator in
 * that intersection double-signed at one height — i.e. is slashable. The theorem is usually a paper
 * argument plus an ad-hoc slashing script; the >= 1/3 culpability is asserted, not extracted as a
 * first-class, verifiable artifact with a published stake-coverage guarantee.
 *
 * This module turns that into evidence: from two finalized verdicts it (1) extracts the
 * cryptographically-verified double-signers (reusing detectEquivocations + verifyEquivocationProof,
 * so every counted validator has two VERIFIED same-height attestations on the two distinct blocks),
 * (2) sums their BigInt stake (ADR-0027 exact stake), and (3) checks that sum >= ceil(total/3) — the
 * accountable-safety guarantee, computed and reported rather than assumed.
 *
 * Additive consensus-layer artifact: no governance / govern-the-verb surface, no in-gate
 * cross-decision state, no wire/KAT/`Ps1` change. Strictly MORE evidence — it never relaxes a check.
 * The `finalized` precondition on each input is the caller's (obtained from the light-client finality
 * verifier); the extractor independently verifies the equivocation signatures and the >= 1/3 coverage.
 */

import { blockHash } from './chain.js'
import {
  detectEquivocations,
  verifyEquivocationProof,
  type EquivocationProof,
} from './equivocation.js'
import { stakeOf, totalStake } from './sortition.js'
import type { FinalizedBlock, ValidatorSet } from './types.js'

export interface AccountableSafetyReport {
  /** True iff the inputs are two distinct, same-height, finalized blocks (a real safety conflict). */
  readonly conflict: boolean
  readonly height: number
  readonly blockHashA: string
  readonly blockHashB: string
  /** Cryptographically-verified slashable proofs, one per culpable validator. */
  readonly proofs: readonly EquivocationProof[]
  /** Summed BigInt stake of the culpable (double-signing) validators. */
  readonly culpableStake: bigint
  readonly totalStake: bigint
  /** ceil(totalStake / 3) — the accountable-safety floor. */
  readonly oneThirdThreshold: bigint
  /** The guarantee: culpableStake >= ceil(total/3). MUST hold for two genuine >= 2/3 quorums. */
  readonly meetsOneThird: boolean
  readonly reasons: readonly string[]
}

/**
 * Extract the slashable validator set proving accountable safety for two finalized blocks at one
 * height. Pure, total, never throws.
 */
export function extractSlashableSet(
  a: FinalizedBlock,
  b: FinalizedBlock,
  set: ValidatorSet,
): AccountableSafetyReport {
  const reasons: string[] = []
  const total = totalStake(set)
  const oneThirdThreshold = (total + 2n) / 3n // ceil(total / 3) for total >= 0

  const hA = blockHash(a.block.header)
  const hB = blockHash(b.block.header)
  if (a.hash !== hA || b.hash !== hB) {
    reasons.push('a provided block hash does not match the recomputed header hash')
  }
  if (a.block.header.height !== b.block.header.height) {
    reasons.push('blocks are at different heights — not a same-height finality conflict')
  }
  if (hA === hB) reasons.push('blocks are identical — no conflict')
  if (!a.finalized || !b.finalized) {
    reasons.push('both blocks must be finalized (>= 2/3 stake) to invoke accountable safety')
  }

  const conflict = reasons.length === 0

  let proofs: readonly EquivocationProof[] = []
  let culpableStake = 0n
  if (conflict) {
    // Only count cryptographically-verified double-signers (sigs + same-height bound checked).
    proofs = detectEquivocations(a.block, a.attestations, b.block, b.attestations).filter((p) =>
      verifyEquivocationProof(p, set),
    )
    const counted = new Set<string>()
    for (const p of proofs) {
      if (counted.has(p.validator)) continue
      counted.add(p.validator)
      culpableStake += stakeOf(set, p.validator)
    }
  }

  const meetsOneThird = conflict && culpableStake >= oneThirdThreshold
  if (conflict && !meetsOneThird) {
    reasons.push(
      `accountable-safety floor not met: culpable stake ${culpableStake} < ceil(total/3) ` +
        `${oneThirdThreshold} — the inputs were not two genuine >= 2/3 quorums`,
    )
  }

  return {
    conflict,
    height: a.block.header.height,
    blockHashA: hA,
    blockHashB: hB,
    proofs,
    culpableStake,
    totalStake: total,
    oneThirdThreshold,
    meetsOneThird,
    reasons,
  }
}
