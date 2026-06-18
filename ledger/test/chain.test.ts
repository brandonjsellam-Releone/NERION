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
const stakes = [34, 33, 33]
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
    expect(verdict.attestingStake).toBeGreaterThanOrEqual(67)
  })

  it('light client rejects a tampered proposer signature', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('ff'.repeat(32), 0, 1000, proposer)
    const badSig = Uint8Array.from(block.proposerSig)
    badSig[0] = (badSig[0] as number) ^ 0xff
    const tampered = { ...block, proposerSig: badSig }
    const atts = keys.map((k) => ledger.attest(block, k))
    expect(verifyFinalized(tampered, atts, set, GENESIS_PREV).ok).toBe(false)
  })

  it('light client rejects attestations for the wrong head', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const block = ledger.propose('ab'.repeat(32), 0, 1000, proposer)
    const atts = keys.map((k) => ledger.attest(block, k))
    expect(verifyFinalized(block, atts, set, 'cd'.repeat(32)).ok).toBe(false)
  })
})
