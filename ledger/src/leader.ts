// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * VRF leader eligibility + draw seeding (ADR-0004).
 *
 * The leader for `(prevHash, round)` is whoever's PRIVATE VRF output β over
 * `vrfAlpha(prevHash, round)` lands in their own pubkey-sorted cumulative-stake
 * interval. This is stake-weighted (P[eligible] = stake/total, so the expected
 * number of eligible leaders per round is 1), UNPREDICTABLE until the proof is
 * revealed (β needs the validator's VRF secret key), and VERIFIABLE by anyone
 * holding the ValidatorSet (recompute α, RFC-9381-verify the proof to recover β,
 * then check the interval). The stake-weighting + sybil-resistance are identical
 * to the old `selectLeader`; only the index source changes from a public hash to
 * the private β. Empty rounds (0 eligible) are resolved by the view-change.
 */

import { encodeCanonical, signerFor } from '../../crypto/src/index.js'
import type { Bytes } from '../../crypto/src/index.js'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { totalStake, totalStakeBig, stakeOf } from './sortition.js'
import type { ValidatorSet, ViewChangeCert } from './types.js'

/** The VRF input α for a draw. Mirrors the old sortition seed preimage. */
export function vrfAlpha(prevHash: string, round: number): Bytes {
  return encodeCanonical(['polarseek-vrf-v1', prevHash, round])
}

/**
 * True iff `proposer` (a validator pubkey) is VRF-eligible for the draw that
 * produced `beta` — i.e. `beta mod totalStake` falls in `proposer`'s own
 * cumulative-stake interval (pubkey-sorted for order-independence). `beta` must
 * already have been recovered from a verified RFC 9381 proof.
 */
export function vrfLeaderEligible(set: ValidatorSet, proposer: string, beta: Bytes): boolean {
  const total = totalStake(set)
  if (total <= 0) return false
  const x = BigInt('0x' + bytesToHex(beta)) % BigInt(total)
  const sorted = [...set.validators].sort((a, b) =>
    a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0,
  )
  let acc = 0n
  for (const v of sorted) {
    acc += BigInt(v.stake)
    if (x < acc) return v.pubkey === proposer
  }
  return false
}

/** Tie-break priority when more than one validator is eligible: LOWER β wins. */
export function vrfPriority(beta: Bytes): bigint {
  return BigInt('0x' + bytesToHex(beta))
}

/** Message a validator signs to vote a round timed out (suite-bound, distinct tag). */
export function viewChangeMessage(
  suite: string,
  height: number,
  prevHash: string,
  round: number,
): Bytes {
  return encodeCanonical(['polarseek-timeout-v1', suite, height, prevHash, round])
}

function safeVerifyTimeout(suite: string, sig: Bytes, msg: Bytes, pub: Bytes): boolean {
  try {
    return signerFor(suite).verify(sig, msg, pub)
  } catch {
    return false
  }
}

/**
 * Verify a ViewChangeCert: ≥ finality fraction of stake signed a TimeoutVote for
 * exactly `(height, prevHash, certRound)`. Mirrors the attestation quorum — distinct
 * validators, suite-matched signatures, deduped, and STATELESS (consults no clock;
 * a timeout is proven by signatures, never asserted by wall-time).
 */
export function verifyViewChangeCert(
  set: ValidatorSet,
  suite: string,
  height: number,
  prevHash: string,
  certRound: number,
  cert: ViewChangeCert | undefined,
  finalityNum = 2,
  finalityDen = 3,
): boolean {
  if (!cert || cert.round !== certRound) return false
  const total = totalStake(set)
  if (total <= 0) return false
  const counted = new Set<string>()
  let stake = 0n
  for (const v of cert.votes) {
    if (v.suite !== suite) continue // bind to the block's suite (cross-suite hardening)
    if (v.height !== height || v.prevHash !== prevHash || v.round !== certRound) continue
    if (counted.has(v.validator)) continue
    const s = stakeOf(set, v.validator)
    if (s <= 0) continue
    const msg = viewChangeMessage(v.suite, height, prevHash, certRound)
    if (!safeVerifyTimeout(v.suite, v.sig, msg, hexToBytes(v.validator))) continue
    counted.add(v.validator)
    stake += BigInt(Number.isInteger(s) ? s : 0)
  }
  // Exact BigInt finality (LEDGER-PRECISION-001/-002/-004, Team Apex): both the counted cert
  // stake (via `+=`) and the total were previously summed in IEEE-754 before the cross-multiply,
  // so past 2^53 the inequality could flip (a sub-2/3 view-change cert accepted). Sum BOTH as
  // BigInt; fail closed on a zero / malformed total.
  const totalBig = totalStakeBig(set)
  return totalBig > 0n && stake * BigInt(finalityDen) >= BigInt(finalityNum) * totalBig
}
