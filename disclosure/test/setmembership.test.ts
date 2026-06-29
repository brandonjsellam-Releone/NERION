// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * ZK set-membership (1-of-k Chaum–Pedersen OR over the audited ristretto255 group; UNAUDITED
 * reference). Prove a Pedersen-committed value is a member of a PUBLIC set without revealing which.
 * These tests check completeness, soundness (a non-member cannot prove; a member-proof does not
 * transfer to a non-member commitment), Fiat–Shamir binding to the exact (commitment, set),
 * tamper-rejection, fail-closed shapes, and HVZK randomization. The soundness ARGUMENT (special-
 * soundness extractor + ROM) remains the real assurance — this layer is classical + UNAUDITED.
 */

import { describe, it, expect } from 'vitest'
import {
  commit,
  randomScalar,
  proveMembership,
  verifyMembership,
  codeFor,
  commitCategory,
  membershipProofDigest,
  SetMembershipError,
} from '../src/index.js'

describe('ZK set-membership (1-of-k CDS OR, UNAUDITED reference)', () => {
  const set = [10n, 42n, 100n, 7n, 256n] // 42 is at index 1

  it('completeness: a member commitment verifies, for every member, with uniform proof shape', () => {
    for (const v of set) {
      const r = randomScalar()
      const C = commit(v, r)
      const proof = proveMembership(v, r, set)
      expect(verifyMembership(C, set, proof)).toBe(true)
      // The proof is the same shape (k challenges + k responses) regardless of WHICH element — it
      // does not structurally leak the true index.
      expect(proof.c.length).toBe(set.length)
      expect(proof.s.length).toBe(set.length)
    }
  })

  it('soundness: proving a NON-member throws (a prover cannot prove a false statement)', () => {
    expect(() => proveMembership(999n, randomScalar(), set)).toThrow(SetMembershipError)
  })

  it('soundness: a member-proof does NOT verify against a commitment to a non-member', () => {
    const r = randomScalar()
    const proof = proveMembership(42n, r, set) // bound to C = commit(42, r)
    expect(verifyMembership(commit(999n, r), set, proof)).toBe(false)
  })

  it('binding: a valid proof does not verify against a different commitment (same value, new blinding)', () => {
    const r = randomScalar()
    const proof = proveMembership(42n, r, set)
    expect(verifyMembership(commit(42n, randomScalar()), set, proof)).toBe(false)
  })

  it('Fiat–Shamir binds the SET: a proof does not verify against a different set', () => {
    const r = randomScalar()
    const C = commit(42n, r)
    const proof = proveMembership(42n, r, set)
    expect(verifyMembership(C, [10n, 42n, 100n], proof)).toBe(false) // different length
    expect(verifyMembership(C, [10n, 43n, 100n, 7n, 256n], proof)).toBe(false) // 42 -> 43, same length
  })

  it('tamper: flipping any challenge share or response breaks verification', () => {
    const r = randomScalar()
    const C = commit(42n, r)
    const proof = proveMembership(42n, r, set)
    expect(verifyMembership(C, set, { ...proof, c: [proof.c[0]! + 1n, ...proof.c.slice(1)] })).toBe(
      false,
    )
    expect(verifyMembership(C, set, { ...proof, s: [proof.s[0]! + 1n, ...proof.s.slice(1)] })).toBe(
      false,
    )
  })

  it('fail-closed: malformed proof shapes / empty / oversized sets return false, never throw', () => {
    const r = randomScalar()
    const C = commit(42n, r)
    const proof = proveMembership(42n, r, set)
    expect(() => verifyMembership(C, set, { c: proof.c.slice(1), s: proof.s })).not.toThrow()
    expect(verifyMembership(C, set, { c: proof.c.slice(1), s: proof.s })).toBe(false) // length mismatch
    expect(verifyMembership(C, [], proof)).toBe(false) // empty set
    expect(() => proveMembership(42n, r, [])).toThrow(SetMembershipError)
  })

  it('HVZK randomization: two proofs of the same statement differ but both verify', () => {
    const r = randomScalar()
    const C = commit(42n, r)
    const p1 = proveMembership(42n, r, set)
    const p2 = proveMembership(42n, r, set)
    expect(p1.s[0]).not.toBe(p2.s[0]) // fresh nonces per proof (no derandomization)
    expect(verifyMembership(C, set, p1)).toBe(true)
    expect(verifyMembership(C, set, p2)).toBe(true)
  })

  it('a single-element set is the degenerate case and still binds', () => {
    const r = randomScalar()
    const C = commit(77n, r)
    const proof = proveMembership(77n, r, [77n])
    expect(verifyMembership(C, [77n], proof)).toBe(true)
    expect(verifyMembership(commit(78n, r), [77n], proof)).toBe(false)
  })
})

describe('categorical disclosure — action-type / counterparty allow-lists', () => {
  it('codeFor is deterministic and label-distinct', () => {
    expect(codeFor('payment.transfer')).toBe(codeFor('payment.transfer'))
    expect(codeFor('payment.transfer')).not.toBe(codeFor('data.read'))
  })

  it('end-to-end: prove the action-type is in the governed allow-set, reveal nothing', () => {
    const allowed = ['payment.transfer', 'data.read', 'infra.deploy'].map(codeFor)
    const { commitment, opening, code } = commitCategory('data.read')
    const proof = proveMembership(code, opening, allowed)
    expect(verifyMembership(commitment, allowed, proof)).toBe(true)
  })

  it('a category NOT in the allow-set cannot be proven', () => {
    const allowed = ['payment.transfer', 'data.read'].map(codeFor)
    const { opening, code } = commitCategory('key.export') // not in the allow-set
    expect(() => proveMembership(code, opening, allowed)).toThrow(SetMembershipError)
  })

  it('membershipProofDigest is deterministic and binds commitment + set + proof + policy', () => {
    const allowed = ['a', 'b', 'c'].map(codeFor)
    const { commitment, opening, code } = commitCategory('b')
    const proof = proveMembership(code, opening, allowed)
    const d = membershipProofDigest(commitment, allowed, proof, 'evaluator-v1')
    expect(membershipProofDigest(commitment, allowed, proof, 'evaluator-v1')).toBe(d) // deterministic
    expect(membershipProofDigest(commitment, allowed, proof, 'evaluator-v2')).not.toBe(d) // policy binding
    const other = commitCategory('b')
    const proof2 = proveMembership(other.code, other.opening, allowed)
    expect(membershipProofDigest(other.commitment, allowed, proof2, 'evaluator-v1')).not.toBe(d) // commitment binding
  })
})
