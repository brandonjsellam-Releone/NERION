// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { commit, proveBelow, verifyBelow, RangeProofError, randomScalar } from '../src/index.js'

describe('ZK range proof — amount < threshold (audited group, unaudited protocol)', () => {
  it('verifies for amounts below the threshold (hiding the amount)', () => {
    for (const amount of [0n, 1n, 40n, 99n]) {
      const r = randomScalar()
      const C = commit(amount, r)
      const proof = proveBelow(amount, r, 100n)
      expect(verifyBelow(C, 100n, proof)).toBe(true)
    }
  })

  it('an honest prover cannot prove an amount that is NOT below the threshold', () => {
    const r = randomScalar()
    expect(() => proveBelow(100n, r, 100n)).toThrow(RangeProofError)
    expect(() => proveBelow(250n, r, 100n)).toThrow(RangeProofError)
  })

  it('rejects out-of-range / negative amounts and oversized thresholds (closes the mod-L gap)', () => {
    const r = randomScalar()
    // amount must be proven in [0, 2^n) too — not just diff. A "negative"/huge
    // mod-L amount can no longer be smuggled through.
    expect(() => proveBelow(-1n, r, 100n)).toThrow(RangeProofError)
    expect(() => proveBelow(1n << 32n, r, 100n)).toThrow(RangeProofError)
    expect(() => proveBelow(5n, r, (1n << 32n) + 1n)).toThrow(RangeProofError)
  })

  it('proves amount itself is in range (two-range construction)', () => {
    const r = randomScalar()
    const proof = proveBelow(40n, r, 100n)
    expect(proof.amount.commitments.length).toBe(proof.n)
    expect(proof.diff.commitments.length).toBe(proof.n)
  })

  it('rejects a proof whose n differs from the verifier-expected n (ZKRANGE-001)', () => {
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n, 16)
    // Prover used n=16; a verifier expecting the protocol-constant n=32 rejects.
    expect(verifyBelow(C, 100n, proof)).toBe(false)
    // It only verifies when the verifier explicitly expects the same n.
    expect(verifyBelow(C, 100n, proof, 16)).toBe(true)
  })

  it('rejects n > 251 on both sides — ZKRANGE-002 wraparound cap (found by Team Apex)', () => {
    const r = randomScalar()
    // n=252 is UNSOUND: L = 2^252 + d (d ≈ 2^124.7), so a negative diff can wrap into
    // [0, 2^n) and a huge amount could falsely prove "< threshold". Both sides cap at 251
    // (2^(n+1) ≤ L): the prover refuses to build it, and the verifier refuses to accept it.
    expect(() => proveBelow(40n, r, 100n, 252)).toThrow(RangeProofError)
    const proof251 = proveBelow(7n, r, 50n, 251) // n=251 is the safe maximum
    expect(verifyBelow(commit(7n, r), 50n, proof251, 251)).toBe(true)
    expect(verifyBelow(commit(7n, r), 50n, proof251, 252)).toBe(false)
  })

  it('rejects a proof checked against the wrong threshold', () => {
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n)
    expect(verifyBelow(C, 50n, proof)).toBe(false)
  })

  it('rejects a proof checked against the wrong commitment', () => {
    const r = randomScalar()
    const proof = proveBelow(40n, r, 100n)
    const wrong = commit(41n, r)
    expect(verifyBelow(wrong, 100n, proof)).toBe(false)
  })

  it('rejects a tampered bit commitment', () => {
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n)
    const tampered = {
      ...proof,
      amount: {
        ...proof.amount,
        commitments: [commit(0n, randomScalar()), ...proof.amount.commitments.slice(1)],
      },
    }
    expect(verifyBelow(C, 100n, tampered)).toBe(false)
  })

  it('rejects a tampered response scalar', () => {
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n)
    const b0 = proof.diff.bits[0]!
    const tampered = {
      ...proof,
      diff: { ...proof.diff, bits: [{ ...b0, s0: b0.s0 + 1n }, ...proof.diff.bits.slice(1)] },
    }
    expect(verifyBelow(C, 100n, tampered)).toBe(false)
  })
})
