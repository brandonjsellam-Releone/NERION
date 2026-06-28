// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CF-2 — accountable-safety extractor tests. Two finalized blocks at one height with overlapping
 * >= 2/3 quorums must yield a slashable set whose BigInt stake is >= ceil(total/3), with every
 * member a cryptographically-verified double-signer. Negatives: identical blocks, non-finalized
 * inputs, different heights, and a bogus "finalized" pair whose overlap is below the floor.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  selectLeader,
  blockHash,
  extractSlashableSet,
  GENESIS_PREV,
  type FinalizedBlock,
  type ValidatorSet,
  type Attestation,
  type Block,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const keys: KeyPair[] = [s.keygen(), s.keygen(), s.keygen()]
const stakes = [34n, 33n, 33n] // total 100; 2/3 = 67; ceil(100/3) = 34
const set: ValidatorSet = {
  validators: keys.map((k, i) => ({ pubkey: bytesToHex(k.publicKey), stake: stakes[i]! })),
}
const v1 = bytesToHex(keys[0]!.publicKey)
const byHex = new Map(keys.map((k) => [bytesToHex(k.publicKey), k]))
const proposer = byHex.get(selectLeader(set, GENESIS_PREV, 0))!

const ledger = new Ledger(set, suite)
// Two CONFLICTING blocks at height 1 (same proposer, same round, different payload → different hash).
const blockA = ledger.propose('aa'.repeat(32), 0, 1000, proposer)
const blockB = ledger.propose('bb'.repeat(32), 0, 1000, proposer)

const fb = (block: Block, atts: readonly Attestation[], stake: bigint): FinalizedBlock => ({
  block,
  hash: blockHash(block.header),
  attestations: atts,
  attestingStake: stake,
  finalized: true,
})

// Quorum A = v1 + v2 (67); Quorum B = v1 + v3 (67); intersection = v1 (34 stake).
const fbA = fb(blockA, [ledger.attest(blockA, keys[0]!), ledger.attest(blockA, keys[1]!)], 67n)
const fbB = fb(blockB, [ledger.attest(blockB, keys[0]!), ledger.attest(blockB, keys[2]!)], 67n)

describe('CF-2 — accountable-safety extractor', () => {
  it('extracts the >= 1/3-stake slashable set from two finalized conflicting blocks', () => {
    const r = extractSlashableSet(fbA, fbB, set)
    expect(r.conflict).toBe(true)
    expect(r.reasons).toEqual([])
    expect(r.proofs.map((p) => p.validator)).toEqual([v1]) // only v1 double-signed
    expect(r.culpableStake).toBe(34n)
    expect(r.totalStake).toBe(100n)
    expect(r.oneThirdThreshold).toBe(34n)
    expect(r.meetsOneThird).toBe(true) // 34 >= ceil(100/3)
  })

  it('every extracted proof is a cryptographically-verified same-height double-sign', () => {
    const r = extractSlashableSet(fbA, fbB, set)
    for (const p of r.proofs) {
      expect(p.height).toBe(0) // fresh-ledger propose() builds the first block at height 0

      expect(p.blockHashA).not.toBe(p.blockHashB)
      expect(p.attA.validator).toBe(p.validator)
      expect(p.attB.validator).toBe(p.validator)
    }
  })

  it('identical blocks are not a conflict', () => {
    const r = extractSlashableSet(fbA, fbA, set)
    expect(r.conflict).toBe(false)
    expect(r.reasons.some((x) => x.includes('identical'))).toBe(true)
  })

  it('non-finalized inputs are not a conflict', () => {
    const notFinal: FinalizedBlock = { ...fbB, finalized: false }
    const r = extractSlashableSet(fbA, notFinal, set)
    expect(r.conflict).toBe(false)
    expect(r.reasons.some((x) => x.includes('finalized'))).toBe(true)
  })

  it('different heights are not a same-height conflict', () => {
    const h2Header = { ...blockB.header, height: 2 }
    const fbH2: FinalizedBlock = {
      ...fbB,
      block: { ...blockB, header: h2Header },
      hash: blockHash(h2Header),
    }
    const r = extractSlashableSet(fbA, fbH2, set)
    expect(r.conflict).toBe(false)
    expect(r.reasons.some((x) => x.includes('different heights'))).toBe(true)
  })

  it('a bogus "finalized" pair whose overlap is below the floor is flagged, not silently accepted', () => {
    // Falsely mark non-quorum attestation sets as finalized; overlap is empty → below ceil(total/3).
    const weakA = fb(blockA, [ledger.attest(blockA, keys[1]!)], 33n) // only v2
    const weakB = fb(blockB, [ledger.attest(blockB, keys[2]!)], 33n) // only v3 — no overlap
    const r = extractSlashableSet(weakA, weakB, set)
    expect(r.conflict).toBe(true) // distinct, same-height, both flagged finalized
    expect(r.culpableStake).toBe(0n)
    expect(r.meetsOneThird).toBe(false)
    expect(r.reasons.some((x) => x.includes('accountable-safety floor not met'))).toBe(true)
  })
})
