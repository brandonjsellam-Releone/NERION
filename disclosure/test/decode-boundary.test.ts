// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Decode-boundary & malleability vectors (audit-prep 2026-06-27 — ZK dossier
 * cross-cutting items "decode boundary" and "proofs are not unique",
 * docs/council/zk-audit-prep-2026-06-27.md).
 *
 * The disclosure layer has NO wire deserializer: `verify*` take already-parsed
 * `Pt`/`bigint`, and the verifier MODS every scalar (zkrange.ts `mod`/`mul`). So
 * scalar canonicality (`c0,c1,s0,s1 < L`) is NOT enforced by the verifier. These
 * tests pin that reality and its containment:
 *
 *   1. Verification is mod-invariant ⇒ a proof carrying a non-canonical scalar
 *      (`s + L`) verifies identically. The EXTERNAL wire→object decode boundary must
 *      therefore reject scalars ≥ L (or rely on the digest binding below) — this is
 *      the malleability surface, not a soundness break.
 *   2. CONTAINMENT: `policyProofDigest` serializes raw scalars, so the malleated proof
 *      yields a DIFFERENT digest. A signed v:2 receipt that binds the proof digest
 *      rejects the byte-level malleation even though `verify` alone accepts it.
 *   3. Policy-layer verification is fail-closed and never throws on an over-range /
 *      non-integer bit width `n` or a structurally-malformed sub-proof (ZK dossier P5;
 *      the ZKRANGE-002 `n ≤ 251` cap is enforced inside `verifyBelow`).
 */

import { describe, it, expect } from 'vitest'
import { ristretto255 } from '@noble/curves/ed25519.js'
import { commit, proveBelow, verifyBelow, randomScalar } from '../src/zkrange.js'
import {
  commitAmount,
  provePolicySatisfaction,
  verifyPolicySatisfaction,
  policyProofDigest,
} from '../src/policyproof.js'

const L = ristretto255.Point.Fn.ORDER
const N = 32

describe('decode boundary: scalar canonicality is not verifier-enforced (ZK dossier cross-cutting)', () => {
  const r = randomScalar()
  const C = commit(40n, r)

  it('verification is mod-invariant: a non-canonical response scalar (s0 + L) still verifies', () => {
    const p = proveBelow(40n, r, 100n, N)
    expect(verifyBelow(C, 100n, p, N)).toBe(true)
    const b0 = p.amount.bits[0]!
    const malleated = {
      ...p,
      amount: { ...p.amount, bits: [{ ...b0, s0: b0.s0 + L }, ...p.amount.bits.slice(1)] },
    }
    // The verifier mods every scalar, so the non-canonical proof verifies identically.
    // This is WHY an external wire-decode boundary must reject scalars ≥ L (or rely on the
    // digest binding asserted next). It is malleability, NOT a soundness break.
    expect(verifyBelow(C, 100n, malleated, N)).toBe(true)
  })

  it('CONTAINMENT: the malleated proof yields a DIFFERENT policyProofDigest (signature catches it)', () => {
    const { commitment, opening } = commitAmount(40n)
    const bounds = { perActionCeiling: 99n, n: N }
    const proof = provePolicySatisfaction(40n, opening, bounds)
    expect(verifyPolicySatisfaction(commitment, bounds, proof)).toBe(true)
    const d0 = policyProofDigest(commitment, bounds, proof, 'evaluator-v1')

    const b0 = proof.ceiling.amount.bits[0]!
    const malleated = {
      ...proof,
      ceiling: {
        ...proof.ceiling,
        amount: {
          ...proof.ceiling.amount,
          bits: [{ ...b0, s0: b0.s0 + L }, ...proof.ceiling.amount.bits.slice(1)],
        },
      },
    }
    // verify still accepts (mod-invariant)...
    expect(verifyPolicySatisfaction(commitment, bounds, malleated)).toBe(true)
    // ...but the serialized digest differs, so a receipt binding the proof rejects it.
    const d1 = policyProofDigest(commitment, bounds, malleated, 'evaluator-v1')
    expect(d1).not.toBe(d0)
  })
})

describe('decode boundary: verification is fail-closed and never throws (ZK dossier P5)', () => {
  const r = randomScalar()
  const C = commit(40n, r)
  const { commitment, opening } = commitAmount(40n)
  const bounds = { perActionCeiling: 99n, n: N }
  const proof = provePolicySatisfaction(40n, opening, bounds)

  it('verifyBelow rejects an over-cap bit width (n > 251, ZKRANGE-002) without throwing', () => {
    const p = proveBelow(40n, r, 100n, N)
    const overcap = { ...p, n: 252 } // claim a width past the 2^(n+1) ≤ L cap
    expect(() => verifyBelow(C, 100n, overcap, 252)).not.toThrow()
    expect(verifyBelow(C, 100n, overcap, 252)).toBe(false)
  })

  it('verifyPolicySatisfaction rejects over-range / non-integer n without throwing', () => {
    for (const bad of [0, -1, 252, 1.5, Number.NaN]) {
      const b = { perActionCeiling: 99n, n: bad }
      expect(() => verifyPolicySatisfaction(commitment, b, proof)).not.toThrow()
      expect(verifyPolicySatisfaction(commitment, b, proof)).toBe(false)
    }
  })

  it('verifyPolicySatisfaction rejects a structurally-malformed ceiling sub-proof without throwing', () => {
    const broken = {
      ...proof,
      ceiling: {
        ...proof.ceiling,
        amount: {
          ...proof.ceiling.amount,
          commitments: proof.ceiling.amount.commitments.slice(1),
        },
      },
    }
    expect(() => verifyPolicySatisfaction(commitment, bounds, broken)).not.toThrow()
    expect(verifyPolicySatisfaction(commitment, bounds, broken)).toBe(false)
  })
})
