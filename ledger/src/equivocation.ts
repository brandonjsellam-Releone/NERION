/**
 * Accountable finality safety (LEDGER-001): equivocation detection + slashing.
 *
 * Stake-finality (≥2/3) is only *safe* if a validator that double-signs two
 * conflicting blocks at the same height is provably caught and slashed — then
 * finalizing two conflicting blocks necessarily exposes ≥1/3 of stake as
 * slashable (Casper-style accountable safety). This module produces and verifies
 * such cryptographic evidence and applies the slash.
 */

import { encodeCanonical, signerFor, type Bytes } from '../../crypto/src/index.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { blockHash } from './chain.js'
import { stakeOf } from './sortition.js'
import type { Attestation, Block, ValidatorSet } from './types.js'

export interface EquivocationProof {
  readonly validator: string
  readonly height: number
  readonly blockHashA: string
  readonly blockHashB: string
  readonly attA: Attestation
  readonly attB: Attestation
}

function attMessage(h: string): Bytes {
  return encodeCanonical(['polarseek-attest-v1', h])
}

function safeVerifyAtt(a: Attestation): boolean {
  try {
    return signerFor(a.suite).verify(a.sig, attMessage(a.blockHash), hexToBytes(a.validator))
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
  if (stakeOf(set, proof.validator) <= 0) return false
  return safeVerifyAtt(proof.attA) && safeVerifyAtt(proof.attB)
}

/** Remove slashed validators, returning a new ValidatorSet (their stake is forfeit). */
export function slash(set: ValidatorSet, validators: readonly string[]): ValidatorSet {
  const bad = new Set(validators)
  return { validators: set.validators.filter((v) => !bad.has(v.pubkey)) }
}
