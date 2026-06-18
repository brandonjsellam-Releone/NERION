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
      commitments: [commit(0n, randomScalar()), ...proof.commitments.slice(1)],
    }
    expect(verifyBelow(C, 100n, tampered)).toBe(false)
  })

  it('rejects a tampered response scalar', () => {
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n)
    const b0 = proof.bits[0]!
    const tampered = { ...proof, bits: [{ ...b0, s0: b0.s0 + 1n }, ...proof.bits.slice(1)] }
    expect(verifyBelow(C, 100n, tampered)).toBe(false)
  })
})
