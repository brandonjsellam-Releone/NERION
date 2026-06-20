// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  selectLeader,
  verifyFinalized,
  detectEquivocations,
  verifyEquivocationProof,
  slash,
  totalStake,
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

describe('accountable finality safety (LEDGER-001)', () => {
  it('detects and slashes validators who double-sign conflicting blocks at one height', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    // Same height, same parent, same (canonical) round — two conflicting payloads.
    const blockA = ledger.propose('aa'.repeat(32), 0, 1000, proposer)
    const blockB = ledger.propose('bb'.repeat(32), 0, 1000, proposer)

    // Every validator double-signs (attests both).
    const attsA = keys.map((k) => ledger.attest(blockA, k))
    const attsB = keys.map((k) => ledger.attest(blockB, k))

    const proofs = detectEquivocations(blockA, attsA, blockB, attsB)
    expect(proofs.length).toBe(3)
    for (const p of proofs) expect(verifyEquivocationProof(p, set)).toBe(true)

    // Slash the double-signers; the remaining honest stake can no longer reach
    // 2/3 for either block — accountable safety.
    const slashed = slash(
      set,
      proofs.map((p) => p.validator),
    )
    expect(totalStake(slashed)).toBe(0)
    expect(verifyFinalized(blockA, attsA, slashed, GENESIS_PREV).finalized).toBe(false)
    expect(verifyFinalized(blockB, attsB, slashed, GENESIS_PREV).finalized).toBe(false)
  })

  it('does not flag honest validators that attest only one block', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const blockA = ledger.propose('cc'.repeat(32), 0, 1000, proposer)
    const blockB = ledger.propose('dd'.repeat(32), 0, 1000, proposer)
    const attsA = keys.map((k) => ledger.attest(blockA, k))
    const attsB: never[] = [] // nobody attested B
    expect(detectEquivocations(blockA, attsA, blockB, attsB).length).toBe(0)
  })

  it('rejects a forged equivocation proof (mismatched/invalid attestations)', () => {
    const ledger = new Ledger(set, suite)
    const proposer = leaderKey(GENESIS_PREV, 0)
    const blockA = ledger.propose('ee'.repeat(32), 0, 1000, proposer)
    const attA = ledger.attest(blockA, keys[0]!)
    // Same blockHash on both sides => not a conflict.
    const bogus = {
      validator: bytesToHex(keys[0]!.publicKey),
      height: 0,
      blockHashA: attA.blockHash,
      blockHashB: attA.blockHash,
      attA,
      attB: attA,
    }
    expect(verifyEquivocationProof(bogus, set)).toBe(false)
  })
})

describe('grind-resistance (LEDGER-002): non-canonical round rejected', () => {
  it('rejects a block whose proposer grinded a non-canonical round', () => {
    const ledger = new Ledger(set, suite)
    // A validator grinds to round 1 to be(come) leader for that round.
    const grinder = leaderKey(GENESIS_PREV, 1)
    const block = ledger.propose('ff'.repeat(32), 1, 1000, grinder) // propose allows it...
    const atts = keys.map((k) => ledger.attest(block, k))
    const verdict = verifyFinalized(block, atts, set, GENESIS_PREV)
    // ...but verification rejects the non-canonical round.
    expect(verdict.ok).toBe(false)
    expect(verdict.reasons.join(' ')).toMatch(/non-canonical round/)
  })
})
