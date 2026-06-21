// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import type { ValidatorSet } from '../../ledger/src/index.js'
import { buildQuorumReceipt, verifyQuorumReceipt, type ReceiptBody } from '../src/index.js'

/**
 * Property-based coverage of k-of-n quorum receipts (Team Apex sweep, 2026-06-21).
 * The example tests pin specific cases; this generalizes the core invariant across
 * RANDOM validator-set sizes, thresholds, and signer subsets (incl. non-members and
 * over-large k): a quorum receipt finalizes **iff** at least k DISTINCT valid member
 * signatures are present — the property that protects decentralized issuance.
 */
const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const epoch = 7

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

// Fixed pool of 6 deterministic keypairs (avoid per-run keygen cost).
const POOL: KeyPair[] = Array.from({ length: 6 }, (_, i) =>
  signer.keygen(new Uint8Array(32).fill(i + 1)),
)
const setOf = (kps: KeyPair[]): ValidatorSet => ({
  validators: kps.map((k) => ({ pubkey: bytesToHex(k.publicKey), stake: 1 })),
})

describe('quorum receipts — properties (randomized)', () => {
  it('finalizes IFF >= k distinct valid MEMBER signatures (across random sets / k / signers)', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 1, max: 6 }), // validator-set size (members = POOL[0..size))
        fc.integer({ min: 1, max: 7 }), // threshold k (sometimes > set size: infeasible)
        fc.uniqueArray(fc.integer({ min: 0, max: 5 }), { minLength: 0, maxLength: 6 }), // signer pool indices
        (setSize, k, signerIdxs) => {
          const set = setOf(POOL.slice(0, setSize))
          const signers = signerIdxs.map((i) => POOL[i]!)
          // distinct valid signers = those that are MEMBERS (index < setSize); indices are unique.
          const distinctMembers = signerIdxs.filter((i) => i < setSize).length
          const r = buildQuorumReceipt(body, set, k, epoch, signers, suite)
          expect(verifyQuorumReceipt(r, set, k, epoch).ok).toBe(distinctMembers >= k)
        },
      ),
      { numRuns: 14 },
    )
  }, 120_000)

  it('a receipt bound to one set is rejected against a different (substituted) set', () => {
    fc.assert(
      fc.property(
        fc.integer({ min: 2, max: 6 }),
        fc.integer({ min: 1, max: 5 }),
        (setSize, drop) => {
          const k = 1
          const fullSet = setOf(POOL.slice(0, setSize))
          const signers = [POOL[0]!]
          const r = buildQuorumReceipt(body, fullSet, k, epoch, signers, suite)
          // Sanity: verifies against its own set.
          expect(verifyQuorumReceipt(r, fullSet, k, epoch).ok).toBe(true)
          // A different (smaller) trusted set => different setId => rejected, even though v0 is still a member.
          const smaller = setOf(POOL.slice(0, Math.max(1, setSize - (drop % setSize))))
          if (smaller.validators.length !== setSize) {
            expect(verifyQuorumReceipt(r, smaller, k, epoch).ok).toBe(false)
          }
        },
      ),
      { numRuns: 10 },
    )
  }, 120_000)
})
