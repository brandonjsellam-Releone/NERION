// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { hexToBytes } from '@noble/hashes/utils.js'
import { prove, verify, vrfPublicKey } from '../src/vrf.js'

/**
 * VRF negative KATs (Team Apex round-4). Explicit malformed-proof vectors that LOCK the guards in
 * ECVRF_verify (RFC 9381 §5.3): non-canonical scalar (s >= L, malleability), zero scalar / zero
 * challenge, an identity/low-order Gamma (uniqueness, VRF-001), an unparseable Gamma, and a
 * valid-but-wrong Gamma. verify() must return null on every one and NEVER throw (it sits behind a
 * stateless consensus verifier). Complements the positive round-trip + the validate-key (public-key)
 * tests — the gap these close is the PROOF side (Gamma validity + scalar canonicity), which a
 * cryptographic auditor probes first.
 */
const seed = new Uint8Array(32).fill(7)
const seed2 = new Uint8Array(32).fill(9)
const alpha = new TextEncoder().encode('polarseek-vrf-alpha')
// Canonical order-2 ed25519 point (0, -1): small-order / torsion-carrying.
const ORDER2 = hexToBytes('ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f')
const pk = vrfPublicKey(seed)
// A genuine 80-byte proof: Gamma(32) || c(16) || s(32). Fresh (and mutable) each call.
const good = (): Uint8Array => prove(seed, alpha).proof

describe('ECVRF verify — negative proof vectors (RFC 9381 §5.3)', () => {
  it('sanity: a genuine proof verifies', () => {
    expect(verify(pk, alpha, good())).not.toBeNull()
  })

  it('rejects a non-canonical scalar s >= L (malleability)', () => {
    const p = good()
    p.set(new Uint8Array(32).fill(0xff), 48) // s = 2^256-1 > L
    expect(verify(pk, alpha, p)).toBeNull()
  })

  it('rejects a zero scalar s = 0', () => {
    const p = good()
    p.set(new Uint8Array(32), 48)
    expect(verify(pk, alpha, p)).toBeNull()
  })

  it('rejects a zero challenge c = 0', () => {
    const p = good()
    p.set(new Uint8Array(16), 32)
    expect(verify(pk, alpha, p)).toBeNull()
  })

  it('rejects an identity / small-order Gamma (uniqueness, VRF-001)', () => {
    const p = good()
    p.set(ORDER2, 0)
    expect(verify(pk, alpha, p)).toBeNull()
  })

  it('rejects an unparseable Gamma without throwing (fail-closed)', () => {
    const p = good()
    p.set(new Uint8Array(32).fill(0xff), 0) // not a canonical point encoding
    expect(verify(pk, alpha, p)).toBeNull()
  })

  it('rejects a valid-but-wrong Gamma (challenge relation)', () => {
    const p = good()
    p.set(vrfPublicKey(seed2), 0) // a real torsion-free point, but not THIS proof's Gamma
    expect(verify(pk, alpha, p)).toBeNull()
  })
})
