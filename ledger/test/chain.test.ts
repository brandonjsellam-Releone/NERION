// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  LedgerError,
  selectLeader,
  verifyFinalized,
  GENESIS_PREV,
  type ValidatorSet,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const keys: KeyPair[] = [s.keygen(), s.keygen(), s.keygen()]
const stakes = [34n, 33n, 33n]
const set: ValidatorSet = {
  validators: keys.map((k, i) => ({ pubkey: bytesToHex(k.publicKey), stake: stakes[i]! })),
}
const byHex = new Map(keys.map((k) => [bytesToHex(k.publicKey), k]))
const leaderKey = (prev: string, round: number): KeyPair =>
  byHex.get(selectLeader(set, prev, round))!

describe('pure-PoS ledger', () => {
  it('proposes by the sortition leader, finalizes at 2/3 stake, and links blocks', () => {
    const ledger = new Ledger(set, suite)

    const proposer1 = leaderKey(GENESIS_PREV, 0)
    const block1 = ledger.propose('aa'.repeat(32), 0, 1000, proposer1)
    const atts1 = keys.map((k) => ledger.attest(block1, k)) // 100 stake
    const fb1 = ledger.submit(block1, atts1)
    expect(fb1.finalized).toBe(true)
    expect(ledger.height()).toBe(1)

    // Second block extends the first.
    const proposer2 = leaderKey(ledger.headHash(), 0)
    const block2 = ledger.propose('bb'.repeat(32), 0, 1001, proposer2)
    expect(block2.header.prevHash).toBe(fb1.hash)
    ledger.submit(
      block2,
      keys.map((k) => ledger.attest(block2, k)),
    )
    expect(ledger.height()).toBe(2)
  })

  it('a non-leader cannot propose', () => {
    const ledger = new Ledger(set, suite)
    const leader = selectLeader(set, GENESIS_PREV, 0)
    const notLeader = keys.find((k) => bytesToHex(k.publicKey) !== leader)!
    expect(() => ledger.propose('cc'.repeat(32), 0, 1000, notLeader)).toThrow(LedgerError)
  })

  it('does not finalize below 2/3 attesting stake', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('dd'.repeat(32), 0, 1000, proposer)
    // A single 33-stake validator (<67) cannot finalize.
    const small = keys.find((k) => bytesToHex(k.publicKey) !== bytesToHex(proposer.publicKey))!
    expect(() => ledger.submit(block, [ledger.attest(block, small)])).toThrow(LedgerError)
  })

  it('light client verifies a finalized block from block + attestations alone', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('ee'.repeat(32), 0, 1000, proposer)
    const atts = keys.slice(0, 2).map((k) => ledger.attest(block, k)) // 34+33 = 67 >= 2/3
    const verdict = verifyFinalized(block, atts, set, GENESIS_PREV)
    expect(verdict.ok).toBe(true)
    expect(verdict.finalized).toBe(true)
    expect(verdict.attestingStake).toBeGreaterThanOrEqual(67n)
  })

  it('F6: rejects an over-cap attestations array fail-closed (decode-side DoS guard)', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('da'.repeat(32), 0, 1000, proposer)
    const one = ledger.attest(block, keys[0]!)
    // length > max(4*|set|, 256): the bound rejects before iterating the array.
    const flood = Array.from({ length: 257 }, () => one)
    const verdict = verifyFinalized(block, flood, set, GENESIS_PREV)
    expect(verdict.ok).toBe(false)
    expect(verdict.finalized).toBe(false)
  })

  it('F-A: finalityNum<=0 does not finalize a zero-attestation block (no zero-stake finalization)', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('be'.repeat(32), 0, 1000, proposer)
    // finalityNum=0 made `attestingStake*den >= 0` true for an EMPTY attestation set (the bug).
    expect(verifyFinalized(block, [], set, GENESIS_PREV, 0, 3).finalized).toBe(false)
    expect(verifyFinalized(block, [], set, GENESIS_PREV, -1, 3).finalized).toBe(false)
  })

  it('F-C: a validator set with duplicate pubkeys is rejected as malformed (not finalized)', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('bf'.repeat(32), 0, 1000, proposer)
    const atts = keys.map((k) => ledger.attest(block, k))
    const dupSet = { ...set, validators: [...set.validators, set.validators[0]!] }
    expect(verifyFinalized(block, atts, dupSet, GENESIS_PREV).finalized).toBe(false)
  })

  it('ADR-0020/B5: an epoch-0 attestation bundle is NOT finalized under the epoch-1 set (cross-epoch substitution)', () => {
    // Same members + stake, different reconfiguration epoch ⇒ different consensusSetId. Attestations
    // signed under epoch 0 bind that setId and fail verification under the epoch-1 set, so the same
    // bundle cannot be replayed to assert finality the epoch-1 set never gave.
    const set0 = { ...set, epoch: 0 }
    const set1 = { ...set, epoch: 1 }
    const ledger0 = new Ledger(set0, suite)
    const proposer = leaderKey(GENESIS_PREV, 0) // leader selection is epoch-independent (same members)
    const block = ledger0.propose('ea'.repeat(32), 0, 1000, proposer)
    const atts = keys.map((k) => ledger0.attest(block, k))
    expect(verifyFinalized(block, atts, set0, GENESIS_PREV).finalized).toBe(true)
    expect(verifyFinalized(block, atts, set1, GENESIS_PREV).finalized).toBe(false)
  })

  it('light client rejects a tampered proposer signature', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('ff'.repeat(32), 0, 1000, proposer)
    const badSig = Uint8Array.from(block.proposerSig)
    badSig[0] = (badSig[0] as number) ^ 0xff
    const tampered = { ...block, proposerSig: badSig }
    const atts = keys.map((k) => ledger.attest(block, k))
    const verdict = verifyFinalized(tampered, atts, set, GENESIS_PREV)
    expect(verdict.ok).toBe(false)
    // LEDGER-FINAL-DECOUPLE-001 (AAC cycle-6): a genuine 2/3 quorum must NOT make `finalized` true when
    // an AUTHORITY check (here the proposer signature) fails — else a bridge/light-client gating on the
    // field named `finalized` would accept an unauthorized block. `finalized` must imply `ok`.
    expect(verdict.finalized).toBe(false)
  })

  it('light client rejects attestations for the wrong head', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('ab'.repeat(32), 0, 1000, proposer)
    const atts = keys.map((k) => ledger.attest(block, k))
    const verdict = verifyFinalized(block, atts, set, 'cd'.repeat(32))
    expect(verdict.ok).toBe(false)
    expect(verdict.finalized).toBe(false) // LEDGER-FINAL-DECOUPLE-001: wrong-head ⇒ not finalized
  })

  it('does not throw on a hostile/bogus suite and returns false (LEDGER-003)', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('1a'.repeat(32), 0, 1000, proposer)
    const bogus = { ...block, suite: 'BOGUS-SUITE-DOES-NOT-EXIST' }
    expect(() => verifyFinalized(bogus, [], set, GENESIS_PREV)).not.toThrow()
    expect(verifyFinalized(bogus, [], set, GENESIS_PREV).ok).toBe(false)
  })

  it('LEDGER-PRECISION-001: finality threshold is exact at large stakes (no IEEE-754 false-finalize)', () => {
    // Attesting stake A = 2^52+1 is exactly ONE unit below 2/3 of total: 3*A < 2*total by 1.
    // But Number(3*A) rounds UP to equal Number(2*total), so the old `*`-in-Number check would
    // FALSELY finalize (a safety violation). The BigInt cross-multiply must report NOT finalized.
    const A = 4503599627370497 // 2^52 + 1 (attesting)
    const B = 2251799813685249 // non-attesting; total = 6755399441055746
    const total = A + B
    expect(A * 3 >= 2 * total).toBe(true) // IEEE-754 false-positive (the bug we fixed)
    expect(BigInt(A) * 3n >= 2n * BigInt(total)).toBe(false) // exact: correctly below 2/3
    const k2 = [s.keygen(), s.keygen()]
    const bigSet: ValidatorSet = {
      validators: [
        { pubkey: bytesToHex(k2[0]!.publicKey), stake: BigInt(A) },
        { pubkey: bytesToHex(k2[1]!.publicKey), stake: BigInt(B) },
      ],
    }
    const ledger = new Ledger(bigSet, suite)
    const leaderHex = selectLeader(bigSet, GENESIS_PREV, 0)
    const proposer = k2.find((k) => bytesToHex(k.publicKey) === leaderHex)!
    const block = ledger.propose('a1'.repeat(32), 0, 1000, proposer)
    const attA = ledger.attest(block, k2[0]!) // only the just-below-2/3 validator attests
    const verdict = verifyFinalized(block, [attA], bigSet, GENESIS_PREV)
    expect(verdict.finalized).toBe(false)
  })
})
