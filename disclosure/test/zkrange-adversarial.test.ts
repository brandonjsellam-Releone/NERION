// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { commit, proveBelow, verifyBelow, randomScalar } from '../src/index.js'

/**
 * A37 (Team Apex 21-day sprint): adversarial VERIFIER-side vectors for the range proof.
 * `verifyBelow` must REJECT (return false, and never throw out of the stateless verifier)
 * every malformed / forged proof: a forged CDS challenge split, an identity-point bit
 * commitment, a zeroed Schnorr response, a swapped sub-proof, and cross-statement replay.
 * Complements the honest-path + single-field tamper tests in `zkrange.test.ts`; written
 * against the surfaces the 3-lens zkrange deep-dive enumerated (CDS split, point validity,
 * the Σ Cᵢ·2ⁱ binding, and statement binding).
 */
const N = 32

describe('verifyBelow — adversarial verifier-side vectors (A37)', () => {
  const r = randomScalar()
  const C = commit(40n, r)
  const good = () => proveBelow(40n, r, 100n, N) // a fresh, valid proof of 40 < 100 each call

  it('rejects a forged CDS challenge split (c0 + c1 ≠ c)', () => {
    const p = good()
    const b0 = p.amount.bits[0]!
    const forged = {
      ...p,
      amount: { ...p.amount, bits: [{ ...b0, c0: b0.c0 + 1n }, ...p.amount.bits.slice(1)] },
    }
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects an identity-point bit commitment (breaks the Σ Cᵢ·2ⁱ == target binding)', () => {
    const p = good()
    const identity = commit(0n, 0n) // 0·G + 0·H = the group identity element
    const forged = {
      ...p,
      amount: { ...p.amount, commitments: [identity, ...p.amount.commitments.slice(1)] },
    }
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects a zeroed response scalar (the Schnorr verify equation fails)', () => {
    const p = good()
    const b0 = p.amount.bits[0]!
    const forged = {
      ...p,
      amount: { ...p.amount, bits: [{ ...b0, s0: 0n }, ...p.amount.bits.slice(1)] },
    }
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects a swapped sub-proof (the amount sub-proof presented as the diff sub-proof)', () => {
    const p = good()
    // diff is verified against cDiff = (threshold-1)·G − C, NOT against C — so the amount
    // sub-proof (which sums to C) must fail when presented as the diff sub-proof.
    const swapped = { ...p, diff: p.amount }
    expect(verifyBelow(C, 100n, swapped, N)).toBe(false)
  })

  it('rejects cross-statement replay (a valid proof under a DIFFERENT commitment / threshold / amount)', () => {
    const p = good() // proves 40 < 100, bound to C = commit(40, r)
    expect(verifyBelow(commit(40n, randomScalar()), 100n, p, N)).toBe(false) // different blinding ⇒ different C
    expect(verifyBelow(C, 50n, p, N)).toBe(false) // different threshold (statement + cDiff both differ)
    expect(verifyBelow(commit(41n, r), 100n, p, N)).toBe(false) // different amount, same r
  })

  it('never throws on a structurally-malformed proof — returns false', () => {
    const p = good()
    const shortCommits = {
      ...p,
      amount: { ...p.amount, commitments: p.amount.commitments.slice(1) },
    }
    expect(() => verifyBelow(C, 100n, shortCommits, N)).not.toThrow()
    expect(verifyBelow(C, 100n, shortCommits, N)).toBe(false)

    const emptyBits = { ...p, diff: { ...p.diff, bits: [] } }
    expect(() => verifyBelow(C, 100n, emptyBits, N)).not.toThrow()
    expect(verifyBelow(C, 100n, emptyBits, N)).toBe(false)
  })
})
