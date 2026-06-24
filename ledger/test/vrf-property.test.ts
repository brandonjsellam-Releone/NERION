// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * VRF property-based tests (Nerion A9 DoD).
 *
 * Six fc.assert properties cover the security-critical invariants of
 * ECVRF-EDWARDS25519-SHA512-TAI (RFC 9381, suite 0x03) over arbitrary inputs:
 *
 *   (a) DETERMINISM    — prove is a pure function of (seed, alpha)
 *   (b) UNIQUENESS     — two different seeds produce different beta for the same alpha
 *   (c) KEY-BINDING    — a proof from sk₁ does not verify against pk₂
 *   (d) TAMPER-PI      — one-bit flip anywhere in proof → verify returns null
 *   (e) TAMPER-ALPHA   — one-bit flip in alpha → verify returns null
 *   (f) TAMPER-PK      — one-bit flip in publicKey → verify returns null
 *
 * Each property runs numRuns:50 iterations so the full suite stays fast in CI.
 */

import { describe, it, expect } from 'vitest'
import * as fc from 'fast-check'
import { bytesToHex } from '@noble/hashes/utils.js'
import { prove, verify, vrfPublicKey } from '../src/vrf.js'

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** A fixed-width 32-byte Uint8Array suitable as a VRF seed. */
const seed32 = fc.uint8Array({ minLength: 32, maxLength: 32 })

/**
 * A pair of DISTINCT 32-byte seeds.
 * fc.filter keeps generation deterministic and avoids the degenerate case
 * where both seeds are identical (which would trivially equal betas).
 */
const twoDistinctSeeds = fc
  .tuple(seed32, seed32)
  .filter(([a, b]) => bytesToHex(a) !== bytesToHex(b))

/** Any alpha: 1..64 bytes. */
const alpha64 = fc.uint8Array({ minLength: 1, maxLength: 64 })

/** Any alpha: 0..64 bytes (empty is valid per RFC 9381). */
const alpha64orEmpty = fc.uint8Array({ minLength: 0, maxLength: 64 })

/**
 * Flip bit `bitIdx % (arr.length * 8)` in a copy of arr.
 * Returns the mutated copy; never touches the original.
 */
function flipBit(arr: Uint8Array, bitIdx: number): Uint8Array {
  const copy = arr.slice()
  const safeIdx = Math.abs(bitIdx) % (copy.length * 8)
  const bytePos = Math.floor(safeIdx / 8)
  const bitPos = safeIdx % 8
  copy[bytePos] = (copy[bytePos] as number) ^ (1 << bitPos)
  return copy
}

// ---------------------------------------------------------------------------
// Properties
// ---------------------------------------------------------------------------

describe('VRF property-based tests (A9)', () => {
  // (a) DETERMINISM: same seed + same alpha → identical proof and beta every time.
  it('(a) DETERMINISM: prove(seed, alpha) is deterministic', () => {
    fc.assert(
      fc.property(seed32, alpha64orEmpty, (seed, alpha) => {
        const r1 = prove(seed, alpha)
        const r2 = prove(seed, alpha)
        expect(bytesToHex(r1.proof)).toBe(bytesToHex(r2.proof))
        expect(bytesToHex(r1.beta)).toBe(bytesToHex(r2.beta))
      }),
      { numRuns: 50 },
    )
  })

  // (b) UNIQUENESS: two distinct seeds → different beta for the same alpha.
  it('(b) UNIQUENESS: distinct seeds produce distinct beta', () => {
    fc.assert(
      fc.property(twoDistinctSeeds, alpha64orEmpty, ([seed1, seed2], alpha) => {
        const beta1 = bytesToHex(prove(seed1, alpha).beta)
        const beta2 = bytesToHex(prove(seed2, alpha).beta)
        expect(beta1).not.toBe(beta2)
      }),
      { numRuns: 50 },
    )
  })

  // (c) KEY-BINDING: proof from sk₁ must not verify under pk₂.
  it('(c) KEY-BINDING: proof from sk₁ does not verify under pk₂', () => {
    fc.assert(
      fc.property(twoDistinctSeeds, alpha64, ([seed1, seed2], alpha) => {
        const pk2 = vrfPublicKey(seed2)
        const { proof } = prove(seed1, alpha)
        expect(verify(pk2, alpha, proof)).toBeNull()
      }),
      { numRuns: 50 },
    )
  })

  // (d) TAMPER-PI: one-bit flip anywhere in proof → null.
  it('(d) TAMPER-PI: any single-bit flip in proof → verify returns null', () => {
    fc.assert(
      fc.property(seed32, alpha64, fc.nat({ max: 639 }), (seed, alpha, bitIdx) => {
        // proof is 80 bytes = 640 bits; bitIdx is in [0, 639]
        const pk = vrfPublicKey(seed)
        const { proof } = prove(seed, alpha)
        const bad = flipBit(proof, bitIdx)
        expect(verify(pk, alpha, bad)).toBeNull()
      }),
      { numRuns: 50 },
    )
  })

  // (e) TAMPER-ALPHA: one-bit flip in alpha → null.
  it('(e) TAMPER-ALPHA: any single-bit flip in alpha → verify returns null', () => {
    fc.assert(
      fc.property(seed32, alpha64, fc.nat({ max: 511 }), (seed, alpha, bitIdx) => {
        const pk = vrfPublicKey(seed)
        const { proof } = prove(seed, alpha)
        // bitIdx clamped inside flipBit to alpha.length * 8 (alpha64 gives 1..64 bytes)
        const badAlpha = flipBit(alpha, bitIdx)
        expect(verify(pk, badAlpha, proof)).toBeNull()
      }),
      { numRuns: 50 },
    )
  })

  // (f) TAMPER-PK: one-bit flip in publicKey → null.
  it('(f) TAMPER-PK: any single-bit flip in publicKey → verify returns null', () => {
    fc.assert(
      fc.property(seed32, alpha64, fc.nat({ max: 255 }), (seed, alpha, bitIdx) => {
        // publicKey is 32 bytes = 256 bits; bitIdx is in [0, 255]
        const pk = vrfPublicKey(seed)
        const { proof } = prove(seed, alpha)
        const badPk = flipBit(pk, bitIdx)
        expect(verify(badPk, alpha, proof)).toBeNull()
      }),
      { numRuns: 50 },
    )
  })
})
