// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import type { ValidatorSet } from '../../ledger/src/index.js'
import type { ReceiptBody } from '../src/index.js'
import {
  buildQuorumReceipt,
  verifyQuorumReceipt,
  verifyQuorumReceiptByStake,
  quorumSetId,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)

const body: ReceiptBody = {
  v: 1,
  suite,
  evaluatorVersion: 'v1',
  effect: 'allow',
  tier: 2,
  jurisdiction: 'US',
  timestamp: 1_750_000_000,
  commitments: {
    intent: 'aa',
    capability: 'none',
    policy: 'bb',
    inputHash: 'cc',
    decisionHash: 'dd',
  },
}

const kp = (n: number): KeyPair => signer.keygen(new Uint8Array(32).fill(n))
const setOf = (kps: KeyPair[], stake = 1): ValidatorSet => ({
  validators: kps.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake })),
})

describe('quorum receipts (decentralized k-of-n issuance)', () => {
  const v = [kp(1), kp(2), kp(3)]
  const set = setOf(v)
  const k = 2
  const epoch = 7

  it('k distinct attestations finalize; k-1 do not; no single signer suffices', () => {
    const r2 = buildQuorumReceipt(body, set, k, epoch, [v[0]!, v[1]!], suite)
    expect(verifyQuorumReceipt(r2, set, k, epoch).ok).toBe(true)
    const r1 = buildQuorumReceipt(body, set, k, epoch, [v[0]!], suite)
    expect(verifyQuorumReceipt(r1, set, k, epoch).ok).toBe(false)
  })

  it('a duplicated signer cannot inflate the count', () => {
    const r = buildQuorumReceipt(body, set, k, epoch, [v[0]!], suite)
    const inflated = { ...r, attestations: [r.attestations[0]!, r.attestations[0]!] }
    const verdict = verifyQuorumReceipt(inflated, set, k, epoch)
    expect(verdict.ok).toBe(false)
    expect(verdict.distinctValid).toBe(1)
  })

  it('a non-member attestation is not counted', () => {
    const outsider = kp(9)
    const r = buildQuorumReceipt(body, set, k, epoch, [v[0]!, outsider], suite)
    expect(verifyQuorumReceipt(r, set, k, epoch).ok).toBe(false) // only v0 is a member
  })

  it('rejects a permissive-set substitution at verify (council binding finding)', () => {
    // Attacker controls one real member (v0) + one attacker key, and binds a
    // receipt to an ATTACKER set where both are validators. It is self-consistent
    // against the attacker's own set, but MUST be rejected against the real set.
    const attacker = kp(99)
    const attackerSet = setOf([v[0]!, attacker])
    const forged = buildQuorumReceipt(body, attackerSet, 2, epoch, [v[0]!, attacker], suite)
    expect(verifyQuorumReceipt(forged, attackerSet, 2, epoch).ok).toBe(true)

    const verdict = verifyQuorumReceipt(forged, set, k, epoch)
    expect(verdict.ok).toBe(false)
    expect(verdict.reasons.some((r) => r.includes('substitution'))).toBe(true)
  })

  it('fails closed on a non-positive threshold (k=0 cannot forge with zero signatures)', () => {
    const zero = buildQuorumReceipt(body, set, 0, epoch, [], suite)
    expect(verifyQuorumReceipt(zero, set, 0, epoch).ok).toBe(false) // not 0 >= 0
    const noSig = buildQuorumReceipt(body, set, 1, epoch, [], suite)
    expect(verifyQuorumReceiptByStake(noSig, set, 0, epoch).ok).toBe(false) // stake floor must be > 0
  })

  it('rejects threshold / epoch mismatch even with enough valid signatures', () => {
    const r = buildQuorumReceipt(body, set, k, epoch, [v[0]!, v[1]!], suite)
    expect(verifyQuorumReceipt(r, set, k, epoch + 1).ok).toBe(false) // wrong epoch
    expect(verifyQuorumReceipt(r, set, k + 1, epoch).ok).toBe(false) // wrong threshold
  })

  it('signatures bind the receipt body — tampering is rejected', () => {
    const r = buildQuorumReceipt(body, set, k, epoch, [v[0]!, v[1]!], suite)
    const tampered = { ...r, body: { ...r.body, receipt: { ...r.body.receipt, effect: 'deny' } } }
    expect(verifyQuorumReceipt(tampered, set, k, epoch).ok).toBe(false)
  })

  it('is deterministic / byte-stable across repeated verification', () => {
    const r = buildQuorumReceipt(body, set, k, epoch, [v[0]!, v[1]!], suite)
    expect(JSON.stringify(verifyQuorumReceipt(r, set, k, epoch))).toBe(
      JSON.stringify(verifyQuorumReceipt(r, set, k, epoch)),
    )
  })

  it('stake-weighted variant requires >= stake threshold of distinct valid signers', () => {
    const sset: ValidatorSet = {
      validators: [
        { pubkey: bytesToHex(v[0]!.publicKey), stake: 3 },
        { pubkey: bytesToHex(v[1]!.publicKey), stake: 1 },
        { pubkey: bytesToHex(v[2]!.publicKey), stake: 1 },
      ],
    }
    const r = buildQuorumReceipt(body, sset, 1, epoch, [v[0]!], suite) // v0 alone = stake 3
    expect(verifyQuorumReceiptByStake(r, sset, 3, epoch).ok).toBe(true)
    expect(verifyQuorumReceiptByStake(r, sset, 4, epoch).ok).toBe(false)
  })

  it('quorumSetId is order-independent but stake/k/epoch sensitive', () => {
    const id = quorumSetId(set, k, epoch)
    expect(quorumSetId({ validators: [...set.validators].reverse() }, k, epoch)).toBe(id)
    expect(quorumSetId(setOf(v, 2), k, epoch)).not.toBe(id) // reweighted stake
    expect(quorumSetId(set, k + 1, epoch)).not.toBe(id)
    expect(quorumSetId(set, k, epoch + 1)).not.toBe(id)
  })
})
