/**
 * Verifiable, stake-weighted leader selection.
 *
 * The leader for (prevHash, round) is a deterministic function of a hash seed,
 * mapped onto the cumulative-stake interval — so anyone with the validator set
 * can recompute and verify who was eligible to propose.
 *
 * NOTE: this is a DETERMINISTIC verifiable selection, not a private VRF. A
 * proper ECVRF / PQ-VRF (hiding the leader until reveal) is future work; flagged
 * in docs/STATUS.md.
 */

import { encodeCanonical, SHA3_SHAKE256 } from '../../crypto/src/index.js'
import { bytesToHex } from '@noble/hashes/utils.js'
import type { ValidatorSet } from './types.js'

export function totalStake(set: ValidatorSet): number {
  return set.validators.reduce((a, v) => a + v.stake, 0)
}

export function stakeOf(set: ValidatorSet, pubkey: string): number {
  return set.validators.find((v) => v.pubkey === pubkey)?.stake ?? 0
}

/** Deterministic stake-weighted leader for a (prevHash, round). */
export function selectLeader(set: ValidatorSet, prevHash: string, round: number): string {
  const total = totalStake(set)
  if (total <= 0) throw new Error('validator set has no stake')
  const seed = SHA3_SHAKE256.digest(encodeCanonical(['polarseek-sortition-v1', prevHash, round]))
  const x = Number(BigInt('0x' + bytesToHex(seed)) % BigInt(total))
  // Sort by pubkey so the cumulative interval is order-independent.
  const sorted = [...set.validators].sort((a, b) =>
    a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0,
  )
  let acc = 0
  for (const v of sorted) {
    acc += v.stake
    if (x < acc) return v.pubkey
  }
  return sorted[sorted.length - 1]!.pubkey
}
