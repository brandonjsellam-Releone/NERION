// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import {
  commit,
  proveBelow,
  verifyBelow,
  RangeProofError,
  randomScalar,
  commitAmount,
  provePolicySatisfaction,
  verifyPolicySatisfaction,
} from '../src/index.js'

/**
 * Property-based coverage of the ZK range / policy-satisfaction proofs — the
 * dominant external-audit-risk component (Team Apex sweep, 2026-06-21). The
 * example tests pin specific cases (ZKRANGE-001/002, threshold/commitment
 * binding); these add RANDOMIZED coverage of the completeness ↔ soundness
 * boundary, run at n=16 (smaller bit-length → faster, same protocol logic) with a
 * bounded number of runs so the gate stays tractable.
 */
const N = 16
const MAX = (1n << BigInt(N)) - 1n // 65535

describe('ZK range proof — properties (randomized)', () => {
  it('COMPLETENESS: any amount < threshold verifies, and is bound to n', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 0n, max: MAX - 1n }),
        fc.bigInt({ min: 1n, max: MAX }),
        (a, gap) => {
          const t = a + gap > MAX ? MAX : a + gap // guarantees 0 <= a < t <= MAX
          const r = randomScalar()
          const proof = proveBelow(a, r, t, N)
          // verifies under the correct (commitment, threshold, n) ...
          expect(verifyBelow(commit(a, r), t, proof, N)).toBe(true)
          // ... and is bound to n: a verifier expecting a different n rejects (ZKRANGE-001).
          expect(verifyBelow(commit(a, r), t, proof, 32)).toBe(false)
        },
      ),
      { numRuns: 10 },
    )
  }, 120_000)

  it('SOUNDNESS: an honest prover cannot build a proof for amount >= threshold', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 1n, max: MAX }),
        fc.bigInt({ min: 0n, max: MAX }),
        (t, extra) => {
          const a = t + extra > MAX ? MAX : t + extra // a >= t
          expect(() => proveBelow(a, randomScalar(), t, N)).toThrow(RangeProofError)
        },
      ),
      { numRuns: 25 },
    )
  }, 120_000)

  it('BINDING: a valid proof does not verify against a wrong threshold or commitment', () => {
    fc.assert(
      fc.property(fc.bigInt({ min: 0n, max: MAX - 2n }), (a) => {
        const t = MAX // a < MAX
        const r = randomScalar()
        const proof = proveBelow(a, r, t, N)
        // wrong threshold (FS-bound) ...
        expect(verifyBelow(commit(a, r), t - 1n, proof, N)).toBe(false)
        // ... wrong commitment blinding ...
        expect(verifyBelow(commit(a, randomScalar()), t, proof, N)).toBe(false)
        // ... wrong committed amount.
        expect(verifyBelow(commit(a + 1n, r), t, proof, N)).toBe(false)
      }),
      { numRuns: 8 },
    )
  }, 120_000)
})

describe('policy-satisfaction proof — properties (randomized)', () => {
  it('COMPLETENESS/SOUNDNESS: proves iff amount <= ceiling, bound to its commitment', () => {
    fc.assert(
      fc.property(
        fc.bigInt({ min: 1n, max: 1000n }),
        fc.bigInt({ min: 0n, max: 2000n }),
        (ceiling, a) => {
          const { commitment, opening } = commitAmount(a)
          const bounds = { perActionCeiling: ceiling }
          if (a <= ceiling) {
            const proof = provePolicySatisfaction(a, opening, bounds)
            expect(verifyPolicySatisfaction(commitment, bounds, proof)).toBe(true)
            // bound to its commitment: a different blinding for the same amount fails.
            const other = commitAmount(a).commitment
            expect(verifyPolicySatisfaction(other, bounds, proof)).toBe(false)
          } else {
            expect(() => provePolicySatisfaction(a, opening, bounds)).toThrow()
          }
        },
      ),
      { numRuns: 10 },
    )
  }, 120_000)
})
