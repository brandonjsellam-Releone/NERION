// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  commitAmount,
  commit,
  randomScalar,
  provePolicySatisfaction,
  verifyPolicySatisfaction,
  policyProofDigest,
  type PolicyBounds,
} from '../src/index.js'

describe('policy-satisfaction proof (hidden-amount compliance, UNAUDITED)', () => {
  it('proves amount <= ceiling without revealing the amount; verifies', () => {
    const { commitment, opening } = commitAmount(40n)
    const bounds: PolicyBounds = { perActionCeiling: 100n }
    const proof = provePolicySatisfaction(40n, opening, bounds)
    expect(verifyPolicySatisfaction(commitment, bounds, proof)).toBe(true)
  })

  it('a prover cannot prove an amount above the ceiling', () => {
    const { opening } = commitAmount(150n)
    expect(() => provePolicySatisfaction(150n, opening, { perActionCeiling: 100n })).toThrow()
  })

  it('a valid proof does not verify against a tighter ceiling (bound is FS-bound)', () => {
    const { commitment, opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n })
    expect(verifyPolicySatisfaction(commitment, { perActionCeiling: 30n }, proof)).toBe(false)
  })

  it('does not verify against a different commitment (binding)', () => {
    const { opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n })
    const other = commit(40n, randomScalar()) // same value, different blinding
    expect(verifyPolicySatisfaction(other, { perActionCeiling: 100n }, proof)).toBe(false)
  })

  it('proves the aggregate-cap clause via the homomorphic sum commitment', () => {
    const { commitment, opening } = commitAmount(40n)
    const bounds: PolicyBounds = { perActionCeiling: 100n, aggregate: 50n, aggregateCap: 120n }
    const proof = provePolicySatisfaction(40n, opening, bounds) // 40+50=90 <= 120
    expect(verifyPolicySatisfaction(commitment, bounds, proof)).toBe(true)
    // a different (untrusted) aggregate the verifier supplies breaks the C_sum check
    expect(verifyPolicySatisfaction(commitment, { ...bounds, aggregate: 90n }, proof)).toBe(false)
  })

  it('a prover cannot prove an aggregate over the cap', () => {
    const { opening } = commitAmount(40n)
    expect(() =>
      provePolicySatisfaction(40n, opening, {
        perActionCeiling: 100n,
        aggregate: 90n,
        aggregateCap: 120n, // 40+90 = 130 > 120
      }),
    ).toThrow()
  })

  it('fail-closed: capped policy with no aggregate proof, and stray aggregate proof', () => {
    const { commitment, opening } = commitAmount(40n)
    const uncapped = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n })
    // ceiling-only proof presented to a capped policy -> rejected (no aggregate proof)
    expect(
      verifyPolicySatisfaction(
        commitment,
        { perActionCeiling: 100n, aggregate: 0n, aggregateCap: 50n },
        uncapped,
      ),
    ).toBe(false)
    // capped proof presented to an uncapped policy -> rejected (stray aggregate proof)
    const capped = provePolicySatisfaction(40n, opening, {
      perActionCeiling: 100n,
      aggregate: 0n,
      aggregateCap: 50n,
    })
    expect(verifyPolicySatisfaction(commitment, { perActionCeiling: 100n }, capped)).toBe(false)
  })

  it('fail-closed: an aggregate cap with no aggregate is rejected (cap cannot be silently skipped)', () => {
    const { commitment, opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n })
    // a verifier that sets a cap but omits the trusted aggregate must NOT pass the proof
    expect(
      verifyPolicySatisfaction(commitment, { perActionCeiling: 100n, aggregateCap: 50n }, proof),
    ).toBe(false)
  })

  it('policyProofDigest binds commitment + policy + proof (deterministic, policy-sensitive)', () => {
    const { commitment, opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n })
    const a = policyProofDigest(commitment, proof, 'kernel-v1+policyhashAAAA')
    const b = policyProofDigest(commitment, proof, 'kernel-v1+policyhashAAAA')
    const c = policyProofDigest(commitment, proof, 'kernel-v1+policyhashBBBB')
    expect(a).toBe(b) // deterministic
    expect(a).not.toBe(c) // a proof under one policy id digests differently than another
  })
})
