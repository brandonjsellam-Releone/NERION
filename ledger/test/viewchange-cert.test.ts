// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Range-validation tests for verifyViewChangeCert certRound parameter (A19).
 *
 * verifyViewChangeCert must return false immediately for any certRound that is
 * not a safe integer or is negative — matching the guard already applied in
 * proposeVrf and verifyFinalized for their respective `round` parameters.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { vrfPublicKey, viewChangeMessage, verifyViewChangeCert } from '../src/index.js'
import type { ValidatorSet, TimeoutVote, ViewChangeCert } from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)

/** Minimal single-validator set with ≥1 stake so totalStake > 0. */
function makeSet(): { set: ValidatorSet; pubkey: string; secretKey: Uint8Array } {
  const kp = signer.keygen(new Uint8Array(32).fill(99))
  const pubkey = bytesToHex(kp.publicKey)
  const vrfPub = bytesToHex(vrfPublicKey(new Uint8Array(32).fill(88)))
  const set: ValidatorSet = { validators: [{ pubkey, vrfPubkey: vrfPub, stake: 1n }] }
  return { set, pubkey, secretKey: kp.secretKey }
}

/** Build a valid TimeoutVote for the given round so cert.votes is well-formed. */
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

const PREV = '00'.repeat(32)

describe('verifyViewChangeCert — certRound range validation (A19)', () => {
  it('accepts a valid certRound=0 (baseline positive)', () => {
    const { set, pubkey, secretKey } = makeSet()
    const vote = makeVote(pubkey, secretKey, 0, PREV, 0)
    const cert: ViewChangeCert = { round: 0, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 0, cert)).toBe(true)
  })

  it('accepts a valid certRound=1 (round > 0 positive)', () => {
    const { set, pubkey, secretKey } = makeSet()
    const vote = makeVote(pubkey, secretKey, 0, PREV, 1)
    const cert: ViewChangeCert = { round: 1, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, 1, cert)).toBe(true)
  })

  it('rejects certRound = -1 (negative)', () => {
    const { set, pubkey, secretKey } = makeSet()
    // Build a cert with round=-1 so the shape is otherwise correct; guard fires first.
    const vote: TimeoutVote = {
      height: 0,
      prevHash: PREV,
      round: -1,
      validator: pubkey,
      suite,
      sig: signer.sign(viewChangeMessage(suite, 0, PREV, -1), secretKey),
    }
    const cert: ViewChangeCert = { round: -1, votes: [vote] }
    expect(verifyViewChangeCert(set, suite, 0, PREV, -1, cert)).toBe(false)
  })

  it('rejects certRound = NaN', () => {
    const { set } = makeSet()
    expect(verifyViewChangeCert(set, suite, 0, PREV, NaN, undefined)).toBe(false)
  })

  it('rejects certRound = Infinity', () => {
    const { set } = makeSet()
    expect(verifyViewChangeCert(set, suite, 0, PREV, Infinity, undefined)).toBe(false)
  })

  it('rejects certRound = -Infinity', () => {
    const { set } = makeSet()
    expect(verifyViewChangeCert(set, suite, 0, PREV, -Infinity, undefined)).toBe(false)
  })

  it('rejects certRound = 2^53 + 1 (beyond Number.MAX_SAFE_INTEGER)', () => {
    const { set } = makeSet()
    const unsafe = Number.MAX_SAFE_INTEGER + 1 // 2^53 + 1, not safe
    expect(verifyViewChangeCert(set, suite, 0, PREV, unsafe, undefined)).toBe(false)
  })
})
