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

export function stakeOf(set: ValidatorSet, pubkey: string): number {
  return set.validators.find((v) => v.pubkey === pubkey)?.stake ?? 0
}

/** Deterministic stake-weighted leader for a (prevHash, round). */
export function selectLeader(set: ValidatorSet, prevHash: string, round: number): string {
  const total = totalStake(set)
  if (total <= 0) throw new Error('validator set has no stake')
  const seed = SHA3_SHAKE256.digest(encodeCanonical(['polarseek-sortition-v1', prevHash, round]))
  // BigInt cumulative walk (LEDGER-PRECISION-001, Team Apex 2026-06-21): a Number() cast of the
  // modulo plus a Number `acc` lose precision once total stake exceeds 2^53, skewing leader
  // selection. Plain bigint keeps it exact. (Residual: totalStake()'s Number sum still bounds
  // total to ~2^53; a full bigint-stake migration is tracked in docs/STATUS.md.)
  const x = BigInt('0x' + bytesToHex(seed)) % BigInt(total)
  // Sort by pubkey so the cumulative interval is order-independent.
  const sorted = [...set.validators].sort((a, b) =>
    a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0,
  )
  let acc = 0n
  for (const v of sorted) {
    acc += BigInt(v.stake)
    if (x < acc) return v.pubkey
  }
  return sorted[sorted.length - 1]!.pubkey
}
