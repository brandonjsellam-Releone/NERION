// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  selectLeader,
  detectEquivocations,
  verifyEquivocationProof,
  totalStake,
  GENESIS_PREV,
  type ValidatorSet,
  type Attestation,
} from '../src/index.js'

/**
 * Property-based correspondence between the **machine-checked** TLA+ accountable-
 * safety model (`docs/formal/NerionConsensus.tla`) and the REAL implementation in
 * `ledger/src/equivocation.ts`. The model proves these invariants abstractly over a
 * finite state space; here we assert the SAME invariants hold on the actual code
 * over a randomized space of validator sets and honest/Byzantine attestation
 * patterns — closing the model-is-not-the-implementation gap with evidence.
 *
 * Mirrored invariants:
 *  - NoHonestEquivocation — an honest validator (one block per height) is never flagged.
 *  - Detection-soundness   — detectEquivocations flags EXACTLY the same-height double-signers.
 *  - AccountableSafety      — if two distinct blocks each reach >2/3 stake, the equivocators
 *                             hold >=1/3 of total stake (hence are slashable).
 */

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
// ML-DSA-87 keygen is expensive; generate a fixed pool once and reuse across runs.
const POOL: KeyPair[] = Array.from({ length: 5 }, () => s.keygen())
const POOL_HEX = POOL.map((k) => bytesToHex(k.publicKey))

// role: 0 = honest (attest A only); 1 = honest (attest B only); 2 = Byzantine (attest both).
const validatorArb = fc.array(
  fc.record({ stake: fc.integer({ min: 1, max: 50 }), role: fc.integer({ min: 0, max: 2 }) }),
  { minLength: 3, maxLength: 5 },
)

const stakeOf = (set: ValidatorSet, atts: Attestation[]): bigint =>
  atts.reduce(
    (acc, a) => acc + (set.validators.find((v) => v.pubkey === a.validator)?.stake ?? 0n),
    0n,
  )

describe('accountable-safety invariants — property-based (mirrors the machine-checked TLA+ model on real code)', () => {
  it('NoHonestEquivocation + detection-soundness + AccountableSafety over randomized attestation patterns', () => {
    fc.assert(
      fc.property(validatorArb, (vs) => {
        const n = vs.length
        const set: ValidatorSet = {
          validators: vs.map((v, i) => ({ pubkey: POOL_HEX[i]!, stake: BigInt(v.stake) })),
        }
        const total = totalStake(set)
        const ledger = new Ledger(set, suite)
        const proposer = POOL[POOL_HEX.indexOf(selectLeader(set, GENESIS_PREV, 0))]!
        // Two conflicting blocks: same height/parent/round, different payloads.
        const blockA = ledger.propose('aa'.repeat(32), 0, 1000, proposer)
        const blockB = ledger.propose('bb'.repeat(32), 0, 1000, proposer)

        const attsA: Attestation[] = []
        const attsB: Attestation[] = []
        const byzantine = new Set<string>()
        for (let i = 0; i < n; i++) {
          const role = vs[i]!.role
          if (role === 0) {
            attsA.push(ledger.attest(blockA, POOL[i]!))
          } else if (role === 1) {
            attsB.push(ledger.attest(blockB, POOL[i]!))
          } else {
            attsA.push(ledger.attest(blockA, POOL[i]!))
            attsB.push(ledger.attest(blockB, POOL[i]!))
            byzantine.add(POOL_HEX[i]!)
          }
        }

        const proofs = detectEquivocations(blockA, attsA, blockB, attsB)
        const flagged = new Set(proofs.map((p) => p.validator))

        // Detection-soundness: flagged == exactly the Byzantine double-signers.
        expect([...flagged].sort()).toEqual([...byzantine].sort())
        // NoHonestEquivocation + every emitted proof verifies against the set.
        for (const p of proofs) {
          expect(byzantine.has(p.validator)).toBe(true)
          expect(verifyEquivocationProof(p, set)).toBe(true)
        }

        // AccountableSafety: two distinct blocks both >2/3 stake => equivocators >=1/3 stake.
        const sA = stakeOf(set, attsA)
        const sB = stakeOf(set, attsB)
        if (3n * sA > 2n * total && 3n * sB > 2n * total) {
          const eqStake = [...byzantine].reduce(
            (acc, h) => acc + (set.validators.find((v) => v.pubkey === h)?.stake ?? 0n),
            0n,
          )
          expect(3n * eqStake >= total).toBe(true)
        }
      }),
      { numRuns: 30 },
    )
  })
})
