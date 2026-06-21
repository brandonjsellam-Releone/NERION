// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

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

/**
 * The single canonical round for a height (grind-resistance, LEDGER-002): the
 * leader is fixed by the parent hash, so a proposer cannot choose `round` to
 * make itself leader. (A view-change / timeout liveness fallback for an offline
 * leader is future work — see docs/STATUS.md.)
 */
export function canonicalRound(_height: number): number {
  return 0
}

export function totalStake(set: ValidatorSet): number {
  return set.validators.reduce((a, v) => a + v.stake, 0)
}

/**
 * Exact total stake as BigInt. `totalStake()` reduces in Number and rounds once the sum exceeds
 * 2^53; finality and sortition decisions must be exact, so they sum non-negative integer stakes
 * as BigInt (LEDGER-PRECISION-004, Team Apex sweep — advancing the documented bigint-stake
 * migration at the decision points). Non-integer / negative stakes contribute 0 (malformed).
 */
export function totalStakeBig(set: ValidatorSet): bigint {
  return set.validators.reduce(
    (a, v) => a + BigInt(Number.isInteger(v.stake) && v.stake >= 0 ? v.stake : 0),
    0n,
  )
}

export function stakeOf(set: ValidatorSet, pubkey: string): number {
  return set.validators.find((v) => v.pubkey === pubkey)?.stake ?? 0
}

/** Deterministic stake-weighted leader for a (prevHash, round). */
export function selectLeader(set: ValidatorSet, prevHash: string, round: number): string {
  const total = totalStake(set)
  if (total <= 0) throw new Error('validator set has no stake')
  const totalBig = totalStakeBig(set)
  if (totalBig <= 0n) throw new Error('validator set has no integer stake')
  const seed = SHA3_SHAKE256.digest(encodeCanonical(['polarseek-sortition-v1', prevHash, round]))
  // BigInt cumulative walk over an EXACT bigint total (LEDGER-PRECISION-001 + -004, Team Apex):
  // both the modulo base and the running `acc` are bigint, so leader selection stays exact even
  // once total stake exceeds 2^53 (the Number `total` above is kept only for the > 0 guard).
  const x = BigInt('0x' + bytesToHex(seed)) % totalBig
  // Sort by pubkey so the cumulative interval is order-independent.
  const sorted = [...set.validators].sort((a, b) =>
    a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0,
  )
  let acc = 0n
  for (const v of sorted) {
    acc += BigInt(Number.isInteger(v.stake) && v.stake >= 0 ? v.stake : 0)
    if (x < acc) return v.pubkey
  }
  return sorted[sorted.length - 1]!.pubkey
}
