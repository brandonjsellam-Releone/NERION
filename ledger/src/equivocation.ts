// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Accountable finality safety (LEDGER-001): equivocation detection + slashing.
 *
 * Stake-finality (≥2/3) is only *safe* if a validator that double-signs two
 * conflicting blocks at the same height is provably caught and slashed — then
 * finalizing two conflicting blocks necessarily exposes ≥1/3 of stake as
 * slashable (Casper-style accountable safety). This module produces and verifies
 * such cryptographic evidence and applies the slash.
 */

import { signerFor } from '../../crypto/src/index.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { blockHash, attestMessage } from './chain.js'
import { stakeOf, consensusSetId } from './sortition.js'
import type { Attestation, Block, ValidatorSet } from './types.js'

export interface EquivocationProof {
  readonly validator: string
  readonly height: number
  readonly blockHashA: string
  readonly blockHashB: string
  readonly attA: Attestation
  readonly attB: Attestation
}

/**
 * Decode-side DoS cap on `detectEquivocations`'s input arrays (ADV-002, AAC council review,
 * 2026-07-11). This exported, peer-facing function takes no `ValidatorSet`, so it cannot compute
 * the `max(4*|set|, 256)`-style cap `verifyFinalized`'s F6 guard uses (chain.ts) — this is a fixed,
 * generous constant instead, matching this codebase's other fixed decode-side bounds (e.g.
 * gossip.ts's MAX_ATTESTED_HASHES). LATENT today (confirmed: `detectEquivocations` is called only
 * from tests; GossipNode never calls it, and its own bounded attestation pool is the only place
 * this repo currently produces attestation arrays), but a caller wiring it directly to
 * attacker-controlled input would otherwise pay 2 ML-DSA-87 verifies per produced proof
 * (`verifyEquivocationProof`) with no bound on how many candidates `detectEquivocations` itself
 * will scan first. Callers with a `ValidatorSet` in scope SHOULD additionally pre-bound with the
 * F6 formula before invoking; this constant is the floor when they cannot.
 */
const MAX_ATTESTATIONS_PER_SIDE = 4096

function safeVerifyAtt(a: Attestation, setId: string): boolean {
  try {
    return signerFor(a.suite).verify(
      a.sig,
      attestMessage(a.suite, a.height, a.blockHash, setId),
      hexToBytes(a.validator),
    )
  } catch {
    return false
  }
}

/**
 * Detect validators who attested BOTH of two distinct blocks at the same height.
 * Returns one slashable proof per offending validator.
 */
export function detectEquivocations(
  blockA: Block,
  attsA: readonly Attestation[],
  blockB: Block,
  attsB: readonly Attestation[],
): EquivocationProof[] {
  // ADV-002: bound attacker-controlled input BEFORE any per-entry work — see
  // MAX_ATTESTATIONS_PER_SIDE's docstring. Fail closed (no proofs) on an over-cap side, matching
  // this function's existing "return [] on invalid input" contract (blockA/B mismatch, above).
  if (attsA.length > MAX_ATTESTATIONS_PER_SIDE || attsB.length > MAX_ATTESTATIONS_PER_SIDE) {
    return []
  }
  if (blockA.header.height !== blockB.header.height) return []
  const hA = blockHash(blockA.header)
  const hB = blockHash(blockB.header)
  if (hA === hB) return []

  const byValidatorA = new Map<string, Attestation>()
  for (const a of attsA) if (a.blockHash === hA) byValidatorA.set(a.validator, a)

  const out: EquivocationProof[] = []
  const seen = new Set<string>()
  for (const b of attsB) {
    if (b.blockHash !== hB || seen.has(b.validator)) continue
    const a = byValidatorA.get(b.validator)
    if (a) {
      seen.add(b.validator)
      out.push({
        validator: b.validator,
        height: blockA.header.height,
        blockHashA: hA,
        blockHashB: hB,
        attA: a,
        attB: b,
      })
    }
  }
  return out
}

/** Verify a slashable equivocation proof against the validator set. */
export function verifyEquivocationProof(proof: EquivocationProof, set: ValidatorSet): boolean {
  if (proof.blockHashA === proof.blockHashB) return false
  if (proof.attA.validator !== proof.validator || proof.attB.validator !== proof.validator)
    return false
  if (proof.attA.blockHash !== proof.blockHashA || proof.attB.blockHash !== proof.blockHashB)
    return false
  // Equivocation is double-signing at the SAME height. Honest validators attest
  // one block per height, i.e. many distinct hashes ACROSS heights; without this
  // check two genuine cross-height attestations forge an "equivocation" and slash
  // an HONEST validator — an accountable-safety inversion (LEDGER-EQUIV-001, Team
  // Apex 2026-06-21). Height is bound into each attestation's signature, so a
  // forged height fails safeVerifyAtt below.
  if (proof.attA.height !== proof.attB.height) return false
  if (proof.height !== proof.attA.height) return false
  if (stakeOf(set, proof.validator) <= 0) return false
  // ADR-0020/B5: the attestations must verify under THIS set's id; a stale cross-epoch
  // equivocation proof (signed under a different set) reconstructs to a different message and is
  // rejected — slashing is scoped to the epoch the double-sign occurred in.
  const setId = consensusSetId(set)
  return safeVerifyAtt(proof.attA, setId) && safeVerifyAtt(proof.attB, setId)
}

/**
 * Remove slashed validators, returning a new ValidatorSet (their stake is forfeit).
 *
 * CONTRACT (ADV-003, AAC council review, 2026-07-11): `slash()` is UNCONDITIONAL — it removes
 * every named validator with NO internal proof check. It is a public export (`ledger/src/index.ts`),
 * so any caller can invoke it directly. The caller MUST have independently verified a
 * `verifyEquivocationProof(proof, set)` for EACH validator passed here, against the EXACT `set`
 * argument this call receives — not a proof verified against a different set, and not a stale
 * proof from a different epoch (consensusSetId folds the epoch, so a proof verified against one
 * epoch's set will not silently apply to another's, but only if the SAME `set` is used for both
 * the verify and this call). Every in-repo caller (see equivocation.test.ts, gossip.test.ts)
 * already does this correctly; this is a residual API-surface footgun for a FUTURE caller, not a
 * currently-exploitable path. Folding verification into `slash()` itself (accepting
 * `EquivocationProof[]` instead of bare pubkeys) is deliberately NOT done here — it is a
 * larger, security-sensitive signature change flagged for dedicated review, not a rushed patch.
 */
export function slash(set: ValidatorSet, validators: readonly string[]): ValidatorSet {
  const bad = new Set(validators)
  return { validators: set.validators.filter((v) => !bad.has(v.pubkey)) }
}
