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
import {
  totalStake,
  totalStakeBig,
  stakeIndex,
  consensusSetId,
  safeStake,
  isWellFormedStakeSet,
} from './sortition.js'
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
  if (total <= 0n) return false
  const x = BigInt('0x' + bytesToHex(beta)) % total
  const sorted = [...set.validators].sort((a, b) =>
    a.pubkey < b.pubkey ? -1 : a.pubkey > b.pubkey ? 1 : 0,
  )
  let acc = 0n
  for (const v of sorted) {
    acc += safeStake(v.stake)
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
  setId: string,
): Bytes {
  // ADR-0020/B5: bind the validator-set id (members+stake+epoch) so a timeout vote made under one
  // set/epoch cannot be re-counted by a verifier holding a different set. v2 tag marks the change.
  return encodeCanonical(['polarseek-timeout-v2', suite, height, prevHash, round, setId])
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
  if (!Number.isSafeInteger(certRound) || certRound < 0) return false
  // Fail-closed on a degenerate finality threshold (Team Apex max sweep 2026-06-28, F-A):
  // finalityNum<=0 makes the cross-multiply RHS <= 0, so a ZERO-vote cert would pass. Require
  // 1 <= finalityNum <= finalityDen (parity with verifyFinalized + receipts quorum.ts k<1 guard).
  if (
    !Number.isInteger(finalityNum) ||
    !Number.isInteger(finalityDen) ||
    finalityNum < 1 ||
    finalityDen < 1 ||
    finalityNum > finalityDen
  )
    return false
  if (!cert || cert.round !== certRound) return false
  const total = totalStake(set)
  if (total <= 0n) return false
  // F7 (Team Apex max sweep 2026-06-28): bound attacker-supplied votes on this exported,
  // peer-facing verifier. At most |validators| distinct votes can ever count, so a votes array
  // far larger than the set is junk that only burns CPU (was O(votes·V): uncapped votes, O(V)
  // stakeOf scan per vote, reachable pre-signature from verifyFinalized for any round>0 block).
  // Reject past 4× the set size, fail-closed, before the loop; the O(1) stakeIndex makes each
  // surviving vote an O(1) lookup.
  if (cert.votes.length > Math.max(set.validators.length * 4, 256)) return false
  const stakeBy = stakeIndex(set)
  const counted = new Set<string>()
  const attempted = new Set<string>()
  let stake = 0n
  for (const v of cert.votes) {
    if (v.suite !== suite) continue // bind to the block's suite (cross-suite hardening)
    if (v.height !== height || v.prevHash !== prevHash || v.round !== certRound) continue
    if (counted.has(v.validator)) continue
    const s = stakeBy.get(v.validator) ?? 0n
    if (s <= 0n) continue
    // DOS-VERIFY-001 (round-2 sweep): one PQ verify per distinct validator — duplicate garbage-sig
    // votes for a staked validator otherwise each ran a fresh ML-DSA-87 verify (O(N) attacker CPU).
    if (attempted.has(v.validator)) continue
    attempted.add(v.validator)
    const msg = viewChangeMessage(v.suite, height, prevHash, certRound, consensusSetId(set))
    if (!safeVerifyTimeout(v.suite, v.sig, msg, hexToBytes(v.validator))) continue
    counted.add(v.validator)
    stake += safeStake(s)
  }
  // Exact BigInt finality (LEDGER-PRECISION-001/-002/-004, Team Apex): both the counted cert
  // stake (via `+=`) and the total were previously summed in IEEE-754 before the cross-multiply,
  // so past 2^53 the inequality could flip (a sub-2/3 view-change cert accepted). Sum BOTH as
  // BigInt. Fail closed on a malformed set (non-integer / negative stake) so silent zeroing cannot
  // shrink the denominator and lower the 2/3 threshold (council review).
  const wellFormedSet = isWellFormedStakeSet(set)
  const totalBig = totalStakeBig(set)
  return (
    wellFormedSet && totalBig > 0n && stake * BigInt(finalityDen) >= BigInt(finalityNum) * totalBig
  )
}
