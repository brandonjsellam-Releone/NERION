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

/** Reason a single proof in a {@link slash} batch was NOT applied. */
export type SlashRejectionReason =
  | 'invalid-proof' // verifyEquivocationProof(proof, set) returned false
  | 'duplicate' // an earlier proof in this same batch already got this validator slashed
  | 'verification-error' // verifying this proof threw (malformed/adversarial input) — caught, not propagated

export interface SlashRejection {
  /** proof.validator, or '<malformed>' if the proof itself couldn't be read at all. */
  readonly validator: string
  /** Original input entry, kept for caller-side audit/logging (may be malformed at runtime). */
  readonly proof: EquivocationProof
  readonly reason: SlashRejectionReason
}

/** Full audit trail for one {@link slash} call. */
export interface SlashResult {
  /** New ValidatorSet with every entry in `slashed` removed (stake forfeit). */
  readonly set: ValidatorSet
  /** Validator ids actually removed, in proof-array order. */
  readonly slashed: readonly string[]
  /** Every proof that did NOT result in a removal, and why. */
  readonly rejected: readonly SlashRejection[]
}

/**
 * Decode-side DoS cap on `slash()`'s `proofs` batch (Team Apex council review, 2026-07-14,
 * following the ADV-002 precedent above for `detectEquivocations`). Each non-duplicate proof pays
 * a full `verifyEquivocationProof` call — up to two real ML-DSA-87 signature verifications — so an
 * attacker who knows a public validator id can cheaply construct a large batch of
 * syntactically-plausible-but-forged proofs to force unbounded verification work. Fail closed (a
 * no-op: unchanged set, nothing slashed or recorded) on an over-cap batch, matching
 * `detectEquivocations`'s existing "reject the whole batch before any per-entry work" contract.
 */
const MAX_PROOFS_PER_SLASH = 4096

/**
 * Verify each proof against `set` and slash only the validators with a valid, non-duplicate
 * equivocation proof in this batch (their stake is forfeit).
 *
 * ADV-003 (closed, 2026-07-14): `slash()` previously took a bare list of validator ids and RELIED
 * on the caller having independently called `verifyEquivocationProof(proof, set)` for each one
 * against this exact `set` — a JSDoc convention, not a compiler- or runtime-enforced invariant.
 * `slash()` now takes the proofs themselves and verifies each one internally, against this same
 * `set` argument, via the unmodified `verifyEquivocationProof` — there is no longer any code path
 * that removes a validator without a proof having actually been checked against the set it is
 * being removed from.
 *
 * Never throws, and one bad entry can never affect another: the ENTIRE per-proof body (the
 * duplicate check, the verification call, and both outcomes) is wrapped in a single try/catch.
 * Do NOT narrow this guard to wrap only the `verifyEquivocationProof` call — a proof array element
 * that is itself null/undefined/a non-object (plausible for proofs deserialized off a gossip/wire
 * layer) throws the moment ANY field on it is read, including in the duplicate check or in the
 * push of a rejection record; guarding only the verify call still lets such an entry abort the
 * whole batch (an earlier draft of this design had exactly that gap — found independently by 3
 * adversarial critique passes and 2 external council reviews before this version shipped). In
 * practice `verifyEquivocationProof` only ever throws this way: `stakeOf`, `consensusSetId`, and
 * `safeVerifyAtt` are total/self-catching for any WELL-FORMED proof against any `ValidatorSet` —
 * so a caught `'verification-error'` here specifically means the proof's shape itself was too
 * malformed to evaluate, not a latent bug in verification logic.
 *
 * `proofs` itself (not just its elements) is defended too: a non-array argument is treated as
 * empty rather than throwing on the `for...of`, and a batch over {@link MAX_PROOFS_PER_SLASH} is
 * rejected wholesale before any verification work begins.
 *
 * The returned `set` preserves every field of the input `set` (e.g. `epoch`) via spread — the
 * original unconditional `slash()` silently dropped non-`validators` fields, which would have
 * reset a set's `epoch` to `consensusSetId`'s default (0) after any slash, silently changing the
 * epoch-scoping of every subsequent verification against the result.
 *
 * Invariant (unless the whole batch was rejected for exceeding {@link MAX_PROOFS_PER_SLASH}):
 * `slashed.length + rejected.length === proofs.length`.
 */
export function slash(set: ValidatorSet, proofs: readonly EquivocationProof[]): SlashResult {
  const list = Array.isArray(proofs) ? proofs : []
  if (list.length > MAX_PROOFS_PER_SLASH) return { set, slashed: [], rejected: [] }

  const slashed: string[] = []
  const rejected: SlashRejection[] = []
  const accepted = new Set<string>()

  for (const proof of list) {
    try {
      if (accepted.has(proof.validator)) {
        rejected.push({ validator: proof.validator, proof, reason: 'duplicate' })
        continue
      }
      if (!verifyEquivocationProof(proof, set)) {
        rejected.push({ validator: proof.validator, proof, reason: 'invalid-proof' })
        continue
      }
      accepted.add(proof.validator)
      slashed.push(proof.validator)
    } catch {
      // Any failure while inspecting/verifying this proof — including a fully malformed array
      // element — is a rejection, never a batch-wide abort.
      const id = (proof as EquivocationProof | null | undefined)?.validator ?? '<malformed>'
      rejected.push({ validator: id, proof, reason: 'verification-error' })
    }
  }

  return {
    set: { ...set, validators: set.validators.filter((v) => !accepted.has(v.pubkey)) },
    slashed,
    rejected,
  }
}
