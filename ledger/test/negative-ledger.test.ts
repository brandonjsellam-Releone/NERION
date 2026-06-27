// SPDX-FileCopyrightText: 2026 TRELYAN
// SPDX-License-Identifier: Apache-2.0

/**
 * Negative tests for verifyViewChangeCert (A12).
 *
 * Every test in this file expects REJECTION (return false). The scenarios
 * exercise quorum under-threshold, cross-epoch mismatch, duplicate-vote
 * deduplication, cross-prevHash mismatches, and BigInt boundary precision at
 * exactly the 2/3 finality edge.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { vrfPublicKey, viewChangeMessage, verifyViewChangeCert } from '../src/index.js'
import type { ValidatorSet, TimeoutVote, ViewChangeCert } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)

const PREV = '00'.repeat(32)
const ALT_PREV = 'ff'.repeat(32)

// ─── helpers ──────────────────────────────────────────────────────────────────

/**
 * Generate `count` key-pairs, each seeded deterministically from a distinct
 * single-byte fill. Returns an array of { pubkey, secretKey } objects.
 */
function makeKeys(count: number, seedBase = 10): Array<{ pubkey: string; secretKey: Uint8Array }> {
  return Array.from({ length: count }, (_, i) => {
    const kp = signer.keygen(new Uint8Array(32).fill(seedBase + i))
    return { pubkey: bytesToHex(kp.publicKey), secretKey: kp.secretKey }
  })
}

/**
 * Build a ValidatorSet where each key-pair has `stakePerValidator` stake.
 * A dummy VRF pubkey is attached (mirrors viewchange-cert.test.ts style).
 */
function makeEqualStakeSet(
  keys: Array<{ pubkey: string; secretKey: Uint8Array }>,
  stakePerValidator = 1n,
): ValidatorSet {
  const vrfPub = bytesToHex(vrfPublicKey(new Uint8Array(32).fill(77)))
  return {
    validators: keys.map(({ pubkey }) => ({
      pubkey,
      vrfPubkey: vrfPub,
      stake: stakePerValidator,
    })),
  }
}

/** Build a well-formed, signature-valid TimeoutVote for the given parameters. */
function makeVote(
  pubkey: string,
  secretKey: Uint8Array,
  height: number,
  prevHash: string,
  round: number,
): TimeoutVote {
  return {
    height,
    prevHash,
    round,
    validator: pubkey,
    suite,
    sig: signer.sign(viewChangeMessage(suite, height, prevHash, round), secretKey),
  }
}

// ─── SUB_TWO_THIRDS_QUORUM ────────────────────────────────────────────────────

describe('SUB_TWO_THIRDS_QUORUM — below 2/3 threshold must be rejected', () => {
  /**
   * Three equal-stake validators: total stake = 3n.
   * Only floor(3/3) = 1 signs → stake 1n, threshold needs ≥ 2n (ceil 2/3).
   * Cross-multiply check: 1n * 3n = 3n < 2n * 3n = 6n → REJECT.
   */
  it('rejects a cert where only 1-of-3 equal-stake validators signed (floor(N/3) signers)', () => {
    const keys = makeKeys(3, 20)
    const set = makeEqualStakeSet(keys, 1n)
    // Only the first validator signs — 1/3 of total stake.
    const vote = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    const cert: ViewChangeCert = { round: 0, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('rejects an empty cert (zero signers)', () => {
    const keys = makeKeys(3, 30)
    const set = makeEqualStakeSet(keys, 1n)
    const cert: ViewChangeCert = { round: 0, votes: [] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('rejects when no signers are in the validator set (unknown validators only)', () => {
    const keys = makeKeys(3, 40)
    const set = makeEqualStakeSet(keys, 1n)
    // Outsider key not in the set.
    const outsider = makeKeys(1, 99)[0]!
    const vote = makeVote(outsider.pubkey, outsider.secretKey, 0, PREV, 0)
    const cert: ViewChangeCert = { round: 0, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })
})

// ─── CROSS_EPOCH_CERT ─────────────────────────────────────────────────────────

describe('CROSS_EPOCH_CERT — cert round mismatch must be rejected', () => {
  /**
   * The protocol encodes "epoch" as the cert.round value. verifyViewChangeCert
   * checks `cert.round !== certRound` immediately after the A19 guard —
   * any cert built for one round presented as justifying a DIFFERENT round
   * (the "claimed epoch") must be rejected.
   */
  it('rejects a cert whose round field differs from certRound (round=1 cert passed as round=0)', () => {
    const keys = makeKeys(3, 50)
    const set = makeEqualStakeSet(keys, 1n)
    // Build a quorum-valid cert for round=1.
    const votes = keys
      .slice(0, 2)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 0, PREV, 1))
    const cert: ViewChangeCert = { round: 1, votes }
    // Present it as justifying certRound=0 — epoch/round mismatch.
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('rejects when cert.round is certRound but each vote carries a different round (vote epoch mismatch)', () => {
    const keys = makeKeys(3, 55)
    const set = makeEqualStakeSet(keys, 1n)
    // Votes signed for round=0 but cert.round=1.
    const votes = keys
      .slice(0, 2)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 0, PREV, 0))
    const cert: ViewChangeCert = { round: 1, votes }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 1, cert)).toBe(false)
  })
})

// ─── DUPLICATE_VOTE ───────────────────────────────────────────────────────────

describe('DUPLICATE_VOTE — duplicate validator votes must not inflate quorum', () => {
  /**
   * verifyViewChangeCert deduplicates via `counted` and `attempted` sets.
   * Even if the same validator appears N times in cert.votes, only the FIRST
   * valid sig earns its stake weight. Counted stake must not reach 2/3.
   */
  it('rejects a cert where the same pubkey appears twice and sole signer is 1-of-3 stake', () => {
    const keys = makeKeys(3, 60)
    const set = makeEqualStakeSet(keys, 1n)
    const vote1 = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    // Second entry: SAME pubkey — dedup prevents double-counting.
    const vote2 = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    const cert: ViewChangeCert = { round: 0, votes: [vote1, vote2] }
    // After dedup: only 1/3 of stake counted → rejected.
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('rejects a cert where one validator appears three times (still 1-of-3 stake after dedup)', () => {
    const keys = makeKeys(3, 65)
    const set = makeEqualStakeSet(keys, 1n)
    const votes = [0, 0, 0].map(() => makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0))
    const cert: ViewChangeCert = { round: 0, votes }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('rejects when two distinct validators appear but one is repeated — net 2 unique of 4 = exactly 1/2 < 2/3', () => {
    // 4-validator set with equal stake: 2/4 = 0.5 < 2/3.
    const keys = makeKeys(4, 70)
    const set = makeEqualStakeSet(keys, 1n)
    const v0vote = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    const v1vote = makeVote(keys[1]!.pubkey, keys[1]!.secretKey, 0, PREV, 0)
    const v0dup = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    // Apparent votes: v0, v1, v0 (dup) → effective unique: v0 + v1 = 2/4 stake.
    const cert: ViewChangeCert = { round: 0, votes: [v0vote, v1vote, v0dup] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })
})

// ─── CROSS_PREV_HASH ──────────────────────────────────────────────────────────

describe('CROSS_PREV_HASH — votes with mismatched prevHash must be filtered out', () => {
  /**
   * verifyViewChangeCert checks `v.prevHash !== prevHash` inside the loop.
   * Votes carrying a different prevHash are silently skipped — a quorum of
   * "wrong-chain" votes must never count as finality for the correct chain.
   */
  it('rejects a cert where all votes carry ALT_PREV instead of the expected PREV', () => {
    const keys = makeKeys(3, 80)
    const set = makeEqualStakeSet(keys, 1n)
    // Quorum-sized but signed for ALT_PREV.
    const votes = keys
      .slice(0, 2)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 0, ALT_PREV, 0))
    const cert: ViewChangeCert = { round: 0, votes }
    // Presented for PREV — prevHash mismatch filters every vote.
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('rejects when a mixed cert has quorum for ALT_PREV but only 1-of-3 for PREV', () => {
    const keys = makeKeys(3, 85)
    const set = makeEqualStakeSet(keys, 1n)
    // One vote for PREV (1/3), two votes for ALT_PREV (would be 2/3 but wrong hash).
    const correctVote = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    const wrongVote1 = makeVote(keys[1]!.pubkey, keys[1]!.secretKey, 0, ALT_PREV, 0)
    const wrongVote2 = makeVote(keys[2]!.pubkey, keys[2]!.secretKey, 0, ALT_PREV, 0)
    const cert: ViewChangeCert = { round: 0, votes: [correctVote, wrongVote1, wrongVote2] }
    // Only correctVote survives filtering → 1/3 stake → rejected.
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('rejects a cert signed for the correct height but wrong prevHash — height field alone is not sufficient', () => {
    const keys = makeKeys(3, 90)
    const set = makeEqualStakeSet(keys, 1n)
    const votes = keys
      .slice(0, 2)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 5, ALT_PREV, 0))
    const cert: ViewChangeCert = { round: 0, votes }
    expect(verifyViewChangeCert(set, suite, 5, PREV, 0, cert)).toBe(false)
  })
})

// ─── BIGINT_THRESHOLD_EDGE ────────────────────────────────────────────────────

describe('BIGINT_THRESHOLD_EDGE — BigInt cross-multiply at exactly the 2/3 finality boundary', () => {
  /**
   * With 3 validators each holding 1n stake (totalStake = 3n):
   *   ceil(2/3 * 3) = 2 → minimum stake to pass = 2n
   *   2n * 3n >= 2n * 3n  →  6 >= 6  →  true  (barely sufficient)
   *   1n * 3n >= 2n * 3n  →  3 >= 6  →  false (just below threshold)
   *
   * This validates the BigInt cross-multiply: stake * finalityDen >= finalityNum * totalBig.
   */
  it('PASS — exactly ceil(2/3 * totalStake) signed (2-of-3, boundary inclusive)', () => {
    const keys = makeKeys(3, 95)
    const set = makeEqualStakeSet(keys, 1n)
    // 2 of 3 equal-stake validators sign — exactly at the 2/3 boundary.
    const votes = keys
      .slice(0, 2)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 0, PREV, 0))
    const cert: ViewChangeCert = { round: 0, votes }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(true)
  })

  it('FAIL — exactly ceil(2/3 * totalStake) - 1 signed (1-of-3, one below threshold)', () => {
    const keys = makeKeys(3, 95)
    const set = makeEqualStakeSet(keys, 1n)
    // 1 of 3 equal-stake validators signs — one unit below the 2/3 threshold.
    const vote = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    const cert: ViewChangeCert = { round: 0, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('PASS — 2-of-3 with non-uniform large BigInt stakes, total > 2^53, at exact 2/3 signed stake', () => {
    // Use stakes near the 2^53 boundary to confirm no IEEE-754 precision loss in the cross-multiply.
    const MAX = 9007199254740991n // 2^53 - 1
    const keys = makeKeys(3, 100)
    const set: ValidatorSet = {
      validators: keys.map(({ pubkey }) => ({ pubkey, stake: MAX })),
    }
    // totalStake = 3 * MAX > 2^53. Two validators sign = 2 * MAX stake.
    // Cross-multiply: (2*MAX) * 3 >= 2 * (3*MAX) → 6*MAX >= 6*MAX → true.
    const votes = keys
      .slice(0, 2)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 0, PREV, 0))
    const cert: ViewChangeCert = { round: 0, votes }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(true)
  })

  it('FAIL — 1-of-3 with large BigInt stakes (1/3 < 2/3, exact BigInt arithmetic confirms no false acceptance)', () => {
    const MAX = 9007199254740991n
    const keys = makeKeys(3, 100)
    const set: ValidatorSet = {
      validators: keys.map(({ pubkey }) => ({ pubkey, stake: MAX })),
    }
    // One validator signs = MAX stake out of 3*MAX total.
    // Cross-multiply: MAX * 3 >= 2 * (3*MAX) → 3*MAX >= 6*MAX → false.
    const vote = makeVote(keys[0]!.pubkey, keys[0]!.secretKey, 0, PREV, 0)
    const cert: ViewChangeCert = { round: 0, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('FAIL — 3-of-5 equal stake (0.6 < 2/3 ≈ 0.667), BigInt cross-multiply rejects', () => {
    // 3/5 * 3 = 9/5 = 1.8 < 2 → stake*finalityDen = 3*3 = 9 < finalityNum*total = 2*5 = 10.
    const keys = makeKeys(5, 105)
    const set = makeEqualStakeSet(keys, 1n)
    const votes = keys
      .slice(0, 3)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 0, PREV, 0))
    const cert: ViewChangeCert = { round: 0, votes }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(false)
  })

  it('PASS — 4-of-5 equal stake (0.8 > 2/3), BigInt cross-multiply accepts', () => {
    // 4/5 * 3 = 12/5 = 2.4 > 2 → stake*finalityDen = 4*3 = 12 >= finalityNum*total = 2*5 = 10.
    const keys = makeKeys(5, 105)
    const set = makeEqualStakeSet(keys, 1n)
    const votes = keys
      .slice(0, 4)
      .map(({ pubkey, secretKey }) => makeVote(pubkey, secretKey, 0, PREV, 0))
    const cert: ViewChangeCert = { round: 0, votes }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(true)
  })
})
