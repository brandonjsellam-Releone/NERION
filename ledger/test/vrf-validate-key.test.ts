// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { ed25519 } from '@noble/curves/ed25519.js'
import { hexToBytes } from '@noble/hashes/utils.js'
import { prove, verify, vrfPublicKey } from '../src/vrf.js'

/**
 * VRF-001 (Team Apex post-fix verification, 2026-06-21). ECVRF_verify now performs
 * ECVRF_validate_key (RFC 9381 §5.4.5 / §7.4): the public key — and Gamma — must be
 * non-identity members of the prime-order subgroup. Without it a malicious validator
 * could register a small-order / torsion-carrying VRF key admitting multiple valid
 * outputs per input, grinding leader sortition. (Forgery itself stays blocked by the
 * 128-bit Fiat-Shamir challenge; this closes the UNIQUENESS gap.)
 */
const P = ed25519.Point
const alpha = new TextEncoder().encode('round-7|prevHash')
// The canonical order-2 ed25519 point (0, -1): a small-order, torsion point.
const ORDER2 = P.fromBytes(
  hexToBytes('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f'),
)

describe('VRF-001 — ECVRF_validate_key (prime-order public key required)', () => {
  it('sanity: the order-2 point is small-order / not torsion-free', () => {
    expect(ORDER2.isSmallOrder()).toBe(true)
    expect(ORDER2.isTorsionFree()).toBe(false)
  })

  it('a legitimate key+proof still verifies (legit keys are torsion-free)', () => {
    const seed = new Uint8Array(32).fill(7)
    const { proof, beta } = prove(seed, alpha)
    const got = verify(vrfPublicKey(seed), alpha, proof)
    expect(got).not.toBeNull()
    expect(got).toEqual(beta)
  })

  it('rejects a torsion-carrying public key (legit key + order-2 point)', () => {
    const seed = new Uint8Array(32).fill(9)
    const { proof } = prove(seed, alpha)
    const Ylegit = P.fromBytes(vrfPublicKey(seed))
    const Ybad = Ylegit.add(ORDER2) // same prime-order component, added torsion
    expect(Ybad.isTorsionFree()).toBe(false)
    // The proof was valid under Ylegit; under the torsion-mangled key, verify MUST reject
    // (pre-fix it would skip the key check and fail later, but the explicit reject is the
    // RFC 9381 §5.4.5 guarantee that closes the uniqueness gap).
    expect(verify(Ybad.toBytes(), alpha, proof)).toBeNull()
  })

  it('rejects a pure small-order public key', () => {
    const seed = new Uint8Array(32).fill(3)
    const { proof } = prove(seed, alpha)
    expect(verify(ORDER2.toBytes(), alpha, proof)).toBeNull()
  })
})
