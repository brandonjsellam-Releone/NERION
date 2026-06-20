// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import { prove, verify, vrfPublicKey, VrfError } from '../src/vrf.js'

const seed = new Uint8Array(32).fill(7)
const seed2 = new Uint8Array(32).fill(9)
const alpha = new TextEncoder().encode('polarseek-vrf-alpha')

describe('ECVRF-EDWARDS25519-SHA512-TAI (self-consistency)', () => {
  it('prove → verify round-trips and recovers beta', () => {
    const pk = vrfPublicKey(seed)
    const { proof, beta } = prove(seed, alpha)
    expect(proof.length).toBe(80)
    expect(beta.length).toBe(64)
    const recovered = verify(pk, alpha, proof)
    expect(recovered).not.toBeNull()
    expect(bytesToHex(recovered as Uint8Array)).toBe(bytesToHex(beta))
  })

  it('is deterministic in (seed, alpha)', () => {
    expect(bytesToHex(prove(seed, alpha).proof)).toBe(bytesToHex(prove(seed, alpha).proof))
  })

  it('rejects a tampered proof (Gamma and s)', () => {
    const pk = vrfPublicKey(seed)
    const { proof } = prove(seed, alpha)
    const badGamma = proof.slice()
    badGamma[10] = (badGamma[10] as number) ^ 0xff
    expect(verify(pk, alpha, badGamma)).toBeNull()
    const badS = proof.slice()
    badS[60] = (badS[60] as number) ^ 0xff
    expect(verify(pk, alpha, badS)).toBeNull()
  })

  it('rejects a wrong alpha and a wrong public key', () => {
    const pk = vrfPublicKey(seed)
    const { proof } = prove(seed, alpha)
    expect(verify(pk, new TextEncoder().encode('other'), proof)).toBeNull()
    expect(verify(vrfPublicKey(seed2), alpha, proof)).toBeNull()
  })

  it('different seeds give different beta for the same alpha', () => {
    expect(bytesToHex(prove(seed, alpha).beta)).not.toBe(bytesToHex(prove(seed2, alpha).beta))
  })

  it('rejects a malformed proof length and a bad seed length', () => {
    expect(verify(vrfPublicKey(seed), alpha, new Uint8Array(79))).toBeNull()
    expect(() => prove(new Uint8Array(31), alpha)).toThrow(VrfError)
  })
})
