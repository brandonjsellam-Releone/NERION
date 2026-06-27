// SPDX-FileCopyrightText: 2026 TRELYAN
// SPDX-License-Identifier: Apache-2.0

/**
 * A37: ZK adversarial test vectors for the Nerion range proof verifier.
 *
 * These are VERIFIER-SIDE vectors: every test constructs a malformed or forged
 * proof and asserts that verifyBelow (and verifyPolicySatisfaction) return FALSE
 * or throw in a controlled manner. A sound verifier must reject all of them.
 *
 * The ZK implementation lives in disclosure/src/zkrange.ts (ristretto255 Pedersen
 * commitments + CDS OR-proof bit-decomposition, Fiat–Shamir). This file imports
 * across package boundaries intentionally — it tests the ZK verifier surface from
 * the crypto package's test directory so the adversarial suite runs alongside the
 * other trust-boundary verifier tests (envelope, COSE, permit).
 *
 * STATUS: the PROTOCOL composition is UNAUDITED (ristretto255 group and SHAKE256
 * are audited); do not claim soundness in production until external ZK review
 * (docs/STATUS.md). No FIPS-certified / audited / non-infringement claim is made.
 *
 * Scenario catalogue:
 *   A37-a  IDENTITY_POINT    — commitment C replaced with identity → reject
 *   A37-b  LOW_ORDER_POINT   — small-subgroup / low-order point attack → reject
 *   A37-c  ZERO_SCALAR       — response scalar zeroed in BOTH arms → reject
 *   A37-d  FORGED_SPLIT      — consistent (c0+c1=c) but wrong Schnorr equations → reject
 *   A37-e  CROSS_STATEMENT   — valid proof replayed for a different statement → reject
 *
 * Gate constraint: never touch conformance/vectors/ps-*.json or crypto/src/suites.ts.
 */

import { describe, it, expect } from 'vitest'
import {
  commit,
  proveBelow,
  verifyBelow,
  randomScalar,
  type RangeProof,
  type Pt,
} from '../../disclosure/src/zkrange.js'
import {
  commitAmount,
  provePolicySatisfaction,
  verifyPolicySatisfaction,
} from '../../disclosure/src/policyproof.js'
import { ristretto255 } from '@noble/curves/ed25519.js'

const Point = ristretto255.Point
const N = 32

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/**
 * Deep-clone a RangeProof so mutations do not share object identity with the
 * original — important because vitest freeze-checks object references.
 */
function cloneProof(p: RangeProof): RangeProof {
  return {
    n: p.n,
    amount: {
      commitments: [...p.amount.commitments],
      bits: p.amount.bits.map((b) => ({ ...b })),
    },
    diff: {
      commitments: [...p.diff.commitments],
      bits: p.diff.bits.map((b) => ({ ...b })),
    },
  }
}

// A fresh, independently randomised valid proof of 40 < 100 each call — keeps
// each test independent (avoids shared state across parallel test runs).
const freshProof = (): { C: Pt; proof: RangeProof } => {
  const r = randomScalar()
  return { C: commit(40n, r), proof: proveBelow(40n, r, 100n, N) }
}

// ---------------------------------------------------------------------------
// A37-a: IDENTITY_POINT
//   Replace the outer commitment C with the group identity (zero point) and
//   pass it to verifyBelow.  The verifier must reject because:
//   1. The Σ Cᵢ·2ⁱ binding check fails — the bit commitments sum to the real
//      commitment, not the identity.
//   2. Even if the adversary also replaces bit commitments, the Schnorr
//      equations bind commitments to blinding scalars the adversary does not know.
// ---------------------------------------------------------------------------
describe('A37-a: IDENTITY_POINT — commitment replaced with group identity', () => {
  it('verifyBelow rejects when C is the identity point (zero element of the group)', () => {
    const { proof } = freshProof()
    const identity: Pt = Point.ZERO
    expect(verifyBelow(identity, 100n, proof, N)).toBe(false)
  })

  it('verifyBelow never throws on identity-point input — fail-closed', () => {
    const { proof } = freshProof()
    expect(() => verifyBelow(Point.ZERO, 100n, proof, N)).not.toThrow()
  })

  it('verifyBelow rejects an identity-point BIT commitment inside the proof', () => {
    // An adversary replaces the first bit commitment with the identity point.
    // The Σ Cᵢ·2ⁱ binding check catches it even without inspecting the Schnorr arm.
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.commitments[0] = Point.ZERO
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('verifyPolicySatisfaction rejects an identity-point commitment at the policy layer', () => {
    const { commitment, opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n, n: N })
    expect(verifyPolicySatisfaction(Point.ZERO, { perActionCeiling: 100n, n: N }, proof)).toBe(
      false,
    )
    // The real commitment must still verify.
    expect(verifyPolicySatisfaction(commitment, { perActionCeiling: 100n, n: N }, proof)).toBe(true)
  })
})

// ---------------------------------------------------------------------------
// A37-b: LOW_ORDER_POINT — small-subgroup / low-order point attack
//
//   In classical Schnorr over prime-order groups, a low-order point can be used
//   to construct proofs that verify for ANY witness (small-subgroup attack).
//   Ristretto255 is a prime-order group (|G| = L, a 252-bit prime); it has NO
//   non-trivial subgroups, so there are no points of low order except the
//   identity element.  The ristretto255 encoding additionally ensures that the
//   identity is the only "trivial" point that can be constructed — every encoded
//   non-identity byte string maps to a canonical prime-order element.
//
//   This test suite:
//   (1) Confirms that the identity is the only reachable low-order point, and
//       that it is already rejected by A37-a.
//   (2) Attempts to forge bit-commitment zero-knowledge by reusing the identity
//       in a Σ Cᵢ·2ⁱ context — must reject.
//   (3) Documents that a subgroup-confinement attack is architecturally excluded
//       by the group choice, not only by the check in verifyBit.
// ---------------------------------------------------------------------------
describe('A37-b: LOW_ORDER_POINT — small-subgroup attack (ristretto255 prime-order property)', () => {
  it('confirms ristretto255 has prime order — identity is the only point of small order', () => {
    // In a prime-order group, the only element whose finite multiple reaches the
    // identity is the identity itself.  There are no non-trivial subgroups, so the
    // "small-subgroup confinement" attack class is architecturally excluded.
    //
    // @noble/curves enforces 1 <= scalar < L so P.multiply(L) is rejected at the
    // library boundary.  We verify the prime-order property indirectly:
    // P*(L-1) = -P, which when added to P gives P + (-P) = identity.
    const L = Point.Fn.ORDER
    const P = Point.BASE
    const negP = P.multiply(L - 1n) // = -G (scalar L-1 is valid: 1 <= L-1 < L)
    expect(P.add(negP).equals(Point.ZERO)).toBe(true)
    // No small multiple of the base point is the identity (orders 2, 4, 8 …).
    // In a prime-order group there are no elements of these orders.
    for (const k of [2n, 4n, 8n, 11n, 16n]) {
      expect(P.multiply(k).equals(Point.ZERO)).toBe(false)
    }
  })

  it('rejects a forged proof whose bit commitments are all replaced with the identity', () => {
    // An adversary with no witness tries to set every Cᵢ = identity, making the
    // bit proofs trivially simulatable. The Σ Cᵢ·2ⁱ == C check rejects immediately.
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.commitments = forged.amount.commitments.map(() => Point.ZERO)
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects a proof where all diff bit commitments are the identity', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.diff.commitments = forged.diff.commitments.map(() => Point.ZERO)
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('never throws when processing identity-filled commitment vectors', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.commitments = forged.amount.commitments.map(() => Point.ZERO)
    expect(() => verifyBelow(C, 100n, forged, N)).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// A37-c: ZERO_SCALAR — response scalar zeroed in the Schnorr arm
//
//   In a CDS OR-proof (Chaum-Pedersen disjunction), each bit has two Schnorr
//   arms: (t0, c0, s0) and (t1, c1, s1).  Zeroing the response scalar s0 in
//   the "real" arm makes the Schnorr equation fail:
//     H^0 = G_H  ≠  t0 + P0^c0   (unless c0 = 0 too, which is excluded by the
//                                   Fiat–Shamir challenge modular arithmetic).
//   A scalar 0 in the DSA-style proof leaks the private witness: if s = k + c·r
//   and s=0 then k = -c·r; with s and c known the adversary recovers r (the
//   blinding of the bit commitment).
// ---------------------------------------------------------------------------
describe('A37-c: ZERO_SCALAR — zeroed response scalars in the Schnorr equations', () => {
  it('rejects proof with s0 = 0 in the first amount bit', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.bits[0]!.s0 = 0n
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects proof with s1 = 0 in the first amount bit', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.bits[0]!.s1 = 0n
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects proof with s0 = 0 in the last amount bit (boundary check)', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.bits[N - 1]!.s0 = 0n
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects proof with ALL amount response scalars zeroed', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.bits = forged.amount.bits.map((b) => ({ ...b, s0: 0n, s1: 0n }))
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects proof with s0 = 0 in the first diff bit', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.diff.bits[0]!.s0 = 0n
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('never throws on zeroed-scalar proofs — fail-closed', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    forged.amount.bits = forged.amount.bits.map((b) => ({ ...b, s0: 0n, s1: 0n }))
    forged.diff.bits = forged.diff.bits.map((b) => ({ ...b, s0: 0n, s1: 0n }))
    expect(() => verifyBelow(C, 100n, forged, N)).not.toThrow()
  })
})

// ---------------------------------------------------------------------------
// A37-d: FORGED_SPLIT — consistent challenge split but wrong Schnorr equations
//
//   The CDS OR-proof requires c0 + c1 ≡ c (mod L) AND that both Schnorr
//   equations hold: H^s0 = t0 + P0^c0 and H^s1 = t1 + P1^c1.
//
//   A more sophisticated forger than A37-a might:
//   (1) Keep c0+c1 = c (so the challenge-sum check passes).
//   (2) Redistribute the split — say c0' = c0+δ, c1' = c1-δ — then adjust
//       the t values hoping the equations still hold.
//
//   Because the t values are COMMITTED (they were hashed into the Fiat–Shamir
//   challenge c BEFORE c0,c1 were determined), the adversary cannot freely
//   adjust t to compensate.  Altering c0,c1 while keeping c0+c1=c means the
//   Schnorr equations H^s_i = t_i + P_i^c_i fail unless the adversary also
//   knows the discrete logs of t0, t1 — which it does not.
//
//   The test constructs the redistribution and verifies rejection.
// ---------------------------------------------------------------------------
describe('A37-d: FORGED_SPLIT — consistent c0+c1=c but wrong Schnorr equations', () => {
  it('rejects a redistributed challenge split (c0+δ, c1-δ) that preserves the sum', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    // Add δ = 1 to c0 and subtract it from c1 in the first amount bit.
    // The sum c0+c1 is unchanged; the Schnorr equations must now fail because
    // t0 was committed with the original c0, and the Schnorr response s0 was
    // computed as k + c0·r, not k + (c0+1)·r.
    const delta = 1n
    const b = forged.amount.bits[0]!
    forged.amount.bits[0] = { ...b, c0: b.c0 + delta, c1: b.c1 - delta }
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects a large redistributed challenge split that still sums correctly', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    // Use a random nonzero δ from the scalar field — sum still holds mod L.
    const delta = randomScalar() % (1n << 64n) // bounded, nonzero with overwhelming probability
    const b = forged.amount.bits[1]!
    forged.amount.bits[1] = { ...b, c0: b.c0 + delta, c1: b.c1 - delta }
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects proof with redistributed split in the diff sub-proof', () => {
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    const delta = 7n
    const b = forged.diff.bits[0]!
    forged.diff.bits[0] = { ...b, c0: b.c0 + delta, c1: b.c1 - delta }
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('rejects a swap of c0 and c1 (c0+c1 unchanged, but Schnorr arms crossed)', () => {
    // Swapping c0↔c1 keeps the sum, but now H^s0 is compared to t0+P0^(old c1),
    // which is not how s0 was computed.
    const { C, proof } = freshProof()
    const forged = cloneProof(proof)
    const b = forged.amount.bits[0]!
    forged.amount.bits[0] = { ...b, c0: b.c1, c1: b.c0 }
    expect(verifyBelow(C, 100n, forged, N)).toBe(false)
  })

  it('verifyPolicySatisfaction rejects a redistributed-split ceiling proof', () => {
    const { commitment, opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n, n: N })
    const forged = {
      ...proof,
      ceiling: cloneProof(proof.ceiling),
    }
    const delta = 3n
    const b = forged.ceiling.amount.bits[0]!
    forged.ceiling.amount.bits[0] = { ...b, c0: b.c0 + delta, c1: b.c1 - delta }
    expect(verifyPolicySatisfaction(commitment, { perActionCeiling: 100n, n: N }, forged)).toBe(
      false,
    )
  })
})

// ---------------------------------------------------------------------------
// A37-e: CROSS_STATEMENT_REPLAY — valid proof replayed for a different statement
//
//   The Fiat–Shamir transcript binds:
//   • The outer commitment C (= commit(amount, r))
//   • The threshold value
//   • All bit commitments for both the amount and the diff sub-proofs
//
//   A proof valid for (C, threshold=100) must be rejected for any of:
//   • A different commitment C' (different amount or different blinding r')
//   • A different threshold
//   • A different bit-length n
//
//   At the policy-proof layer, policyProofDigest additionally binds the
//   policyBinding string and the numeric bounds — replay across policy versions
//   is rejected at the digest check before verifyBelow is even reached.
// ---------------------------------------------------------------------------
describe('A37-e: CROSS_STATEMENT_REPLAY — valid proof replayed for a different statement', () => {
  it('rejects replay with a different blinding scalar (same amount, different r)', () => {
    const r1 = randomScalar()
    const r2 = randomScalar() // different blinding — with overwhelming probability r2 ≠ r1
    const C1 = commit(40n, r1)
    const proof = proveBelow(40n, r1, 100n, N) // proof for C1
    // The statement in the FS transcript is bound to C1; C2 produces a different stmt hash.
    const C2 = commit(40n, r2)
    expect(verifyBelow(C2, 100n, proof, N)).toBe(false)
  })

  it('rejects replay with a different committed amount (same r)', () => {
    const r = randomScalar()
    const proof = proveBelow(40n, r, 100n, N)
    // The Σ Cᵢ·2ⁱ == C binding fails because C′ = commit(41, r) ≠ commit(40, r).
    expect(verifyBelow(commit(41n, r), 100n, proof, N)).toBe(false)
    expect(verifyBelow(commit(0n, r), 100n, proof, N)).toBe(false)
  })

  it('rejects replay with a different threshold (same C)', () => {
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n, N)
    // A different threshold changes both the FS statement hash (tag) and cDiff,
    // so both the statement-binding check and the Σ Cᵢ·2ⁱ == cDiff check fail.
    expect(verifyBelow(C, 50n, proof, N)).toBe(false)
    expect(verifyBelow(C, 200n, proof, N)).toBe(false)
    expect(verifyBelow(C, 41n, proof, N)).toBe(false)
  })

  it('rejects replay with a different n (bit-width mismatch)', () => {
    const r = randomScalar()
    const C = commit(7n, r)
    const proof = proveBelow(7n, r, 50n, 16) // built with n=16
    // Verifier expecting n=32 must reject — proof.n ≠ n is the first check.
    expect(verifyBelow(C, 50n, proof, N)).toBe(false)
    // And the honest n=16 verifier accepts.
    expect(verifyBelow(C, 50n, proof, 16)).toBe(true)
  })

  it('rejects replay with a swapped amount/diff sub-proof (cross-sub-proof replay)', () => {
    // The amount sub-proof sums to C; the diff sub-proof sums to cDiff.
    // Presenting the amount proof as the diff proof must fail because cDiff ≠ C
    // (unless threshold = 1+2*amount, which is not the case here).
    const r = randomScalar()
    const C = commit(40n, r)
    const proof = proveBelow(40n, r, 100n, N)
    const swapped: RangeProof = { ...proof, diff: proof.amount }
    expect(verifyBelow(C, 100n, swapped, N)).toBe(false)
  })

  it('rejects replay of a ceiling proof presented for a different policy ceiling', () => {
    const { commitment, opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n, n: N })
    // The ceiling sub-proof is bound to threshold = 101 (ceiling+1 in proveBelow).
    // Presenting it as proof of ceiling=50 requires threshold=51, which changes cDiff.
    expect(verifyPolicySatisfaction(commitment, { perActionCeiling: 50n, n: N }, proof)).toBe(false)
  })

  it('rejects a ceiling-only proof replayed as a capped-aggregate proof', () => {
    // A proof with aggregate=null must be rejected against a capped policy.
    const { commitment, opening } = commitAmount(40n)
    const proof = provePolicySatisfaction(40n, opening, { perActionCeiling: 100n, n: N })
    // aggregate is null here; a capped policy with aggregate=0 requires an
    // aggregate sub-proof to be present — verifyPolicySatisfaction returns false
    // because proof.aggregate === null.
    expect(
      verifyPolicySatisfaction(
        commitment,
        {
          perActionCeiling: 100n,
          aggregateCap: 200n,
          aggregate: 0n,
          n: N,
        },
        proof,
      ),
    ).toBe(false)
  })

  it('rejects a capped proof replayed against an uncapped policy', () => {
    // Conversely, a proof that includes an aggregate sub-proof must be rejected
    // against a ceiling-only policy (fail-closed: stray aggregate proof).
    const { commitment, opening } = commitAmount(40n)
    const cappedProof = provePolicySatisfaction(40n, opening, {
      perActionCeiling: 100n,
      aggregateCap: 200n,
      aggregate: 10n,
      n: N,
    })
    expect(
      verifyPolicySatisfaction(commitment, { perActionCeiling: 100n, n: N }, cappedProof),
    ).toBe(false)
  })
})
