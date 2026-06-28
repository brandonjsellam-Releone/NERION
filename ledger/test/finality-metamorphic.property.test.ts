// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * CF-5 — metamorphic finality oracle (single-implementation arm).
 *
 * Metamorphic relations the light-client finality verdict MUST satisfy over its attestation input,
 * proven against the shipped `verifyFinalized` (the cross-implementation arm vs the Rust ledger is
 * out of scope — no Rust ledger yet):
 *
 *   - DUPLICATE-IDEMPOTENCE: repeating attestations never inflates attesting stake (dedup by
 *     validator) — the no-double-count SAFETY property.
 *   - ORDER-INDEPENDENCE (valid input): permuting an all-valid attestation set leaves the verdict
 *     unchanged.
 *   - JUNK-INVARIANCE: wrong-block / wrong-height / wrong-suite / non-staked attestations are ignored.
 *   - MONOTONICITY: a superset of valid attestations never yields less attesting stake than a subset.
 *
 * It also pins the ONE intentional order-dependence — DOS-VERIFY-001 caps PQ verifies at one per
 * validator, so a garbage-sig attestation placed before a validator's valid one drops that validator
 * — and shows it is LIVENESS-only: it can only LOWER attesting stake, never forge finality.
 *
 * Additive: tests only; `verifyFinalized` is unchanged. No wire / KAT / `Ps1`. UNAUDITED.
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { signerFor, SUITE_IDS, type KeyPair } from '../../crypto/src/index.js'
import {
  Ledger,
  selectLeader,
  verifyFinalized,
  GENESIS_PREV,
  type Attestation,
  type ValidatorSet,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const s = signerFor(suite)
const keys: KeyPair[] = [s.keygen(), s.keygen(), s.keygen()]
const stakes = [34n, 33n, 33n] // total 100; a 2/3 quorum needs >= 67
const set: ValidatorSet = {
  validators: keys.map((k, i) => ({ pubkey: bytesToHex(k.publicKey), stake: stakes[i]! })),
}
const byHex = new Map(keys.map((k) => [bytesToHex(k.publicKey), k]))
const proposer = byHex.get(selectLeader(set, GENESIS_PREV, 0))!
const outsider = s.keygen() // valid signer, but NOT in the set → zero stake

const ledger = new Ledger(set, suite)
const block = ledger.propose('aa'.repeat(32), 0, 1000, proposer)
const validAtts = keys.map((k) => ledger.attest(block, k)) // 4 valid attestations, 100 stake

const vf = (atts: readonly Attestation[]) => verifyFinalized(block, atts, set, GENESIS_PREV)
const baseline = vf(validAtts)

const tamperSig = (a: Attestation): Attestation => {
  const sig = Uint8Array.from(a.sig)
  sig[0] = (sig[0] as number) ^ 0xff
  return { ...a, sig }
}

describe('CF-5 — metamorphic finality oracle', () => {
  it('baseline: all four valid attestations finalize at 100/100 stake', () => {
    expect(baseline.attestingStake).toBe(100n)
    expect(baseline.finalized).toBe(true)
  })

  it('DUPLICATE-IDEMPOTENCE: repeated attestations never inflate stake (no double-count)', () => {
    fc.assert(
      fc.property(
        fc.array(fc.integer({ min: 0, max: 3 }), { minLength: 3, maxLength: 3 }),
        (reps) => {
          const multiset: Attestation[] = []
          validAtts.forEach((a, i) => {
            for (let r = 0; r < reps[i]! + 1; r++) multiset.push(a) // each present 1..4 times
          })
          const v = vf(multiset)
          expect(v.attestingStake).toBe(100n) // 100n bigint constant — independent of repetition count
          expect(v.finalized).toBe(true)
        },
      ),
      { seed: 0x63663501, numRuns: 100 },
    )
  })

  it('ORDER-INDEPENDENCE: any permutation of valid attestations gives the same verdict', () => {
    fc.assert(
      fc.property(fc.shuffledSubarray(validAtts, { minLength: 3, maxLength: 3 }), (perm) => {
        const v = vf(perm)
        expect(v.attestingStake).toBe(baseline.attestingStake)
        expect(v.finalized).toBe(baseline.finalized)
      }),
      { seed: 0x63663502, numRuns: 100 },
    )
  })

  it('JUNK-INVARIANCE: wrong-block / height / suite / non-staked attestations are ignored', () => {
    const junk: Attestation[] = [
      { ...validAtts[0]!, blockHash: 'ff'.repeat(32) }, // wrong block
      { ...validAtts[1]!, height: 999 }, // wrong height
      { ...validAtts[2]!, suite: SUITE_IDS.PS_1 }, // wrong suite
      ledger.attest(block, outsider), // valid sig, but zero-stake (not in set)
    ]
    const v = vf([...validAtts, ...junk])
    expect(v.attestingStake).toBe(100n)
    expect(v.finalized).toBe(true)
  })

  it('MONOTONICITY: a superset of valid attestations never yields less stake', () => {
    fc.assert(
      fc.property(
        fc.subarray(validAtts, { minLength: 0, maxLength: 3 }),
        fc.subarray(validAtts, { minLength: 0, maxLength: 3 }),
        (a, b) => {
          const union = [...new Set([...a, ...b])]
          expect(vf(union).attestingStake).toBeGreaterThanOrEqual(vf(a).attestingStake)
        },
      ),
      { seed: 0x63663503, numRuns: 100 },
    )
  })

  it('DOS-VERIFY-001 tradeoff: a garbage-sig before a validator drops it — liveness-only, never forges finality', () => {
    // A minimal 2-of-3 quorum: v0(34) + v1(33) = 67 (exactly the 2/3 floor).
    const v0 = validAtts[0]! // stake 34
    const v1 = validAtts[1]! // stake 33
    const garbage0 = tamperSig(v0)
    // garbage FIRST → v0's single verify slot is spent on the bad sig → v0 dropped → 33/100, NOT finalized.
    const garbageFirst = vf([garbage0, v0, v1])
    // valid FIRST → v0 counts → 67/100, finalized.
    const validFirst = vf([v0, garbage0, v1])
    expect(garbageFirst.attestingStake).toBe(33n)
    expect(garbageFirst.finalized).toBe(false)
    expect(validFirst.attestingStake).toBe(67n)
    expect(validFirst.finalized).toBe(true)
    // SAFETY: the order-dependence can only LOWER counted stake, never forge a higher one.
    expect(garbageFirst.attestingStake).toBeLessThan(validFirst.attestingStake)
  })

  it('BOUNDARY: quorum is exact at the 2/3 floor (67 finalizes, 66 does not)', () => {
    const q67 = vf([validAtts[0]!, validAtts[1]!]) // 34 + 33 = 67
    expect(q67.attestingStake).toBe(67n)
    expect(q67.finalized).toBe(true)
    const q66 = vf([validAtts[1]!, validAtts[2]!]) // 33 + 33 = 66
    expect(q66.attestingStake).toBe(66n)
    expect(q66.finalized).toBe(false)
  })

  it('BOUNDARY: an empty / zero-stake validator set fails closed (no finality, no div-by-zero)', () => {
    const empty = verifyFinalized(block, validAtts, { validators: [] }, GENESIS_PREV)
    expect(empty.attestingStake).toBe(0n)
    expect(empty.finalized).toBe(false)
  })
})
