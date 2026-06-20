// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { getKem, implementedKemIds, KEM_IDS } from '../src/kem.js'
import { NotImplementedError } from '../src/errors.js'

describe.each(implementedKemIds())('hybrid KEM %s', (id) => {
  const kem = getKem(id)

  it('encapsulate/decapsulate yields the same shared secret', () => {
    const { publicKey, secretKey } = kem.keygen()
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
    const recovered = kem.decapsulate(cipherText, secretKey)
    expect(Buffer.from(recovered)).toEqual(Buffer.from(sharedSecret))
    expect(sharedSecret.length).toBeGreaterThanOrEqual(32)
  })

  it('a tampered ciphertext does not recover the shared secret', () => {
    const { publicKey, secretKey } = kem.keygen()
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
    const bad = Uint8Array.from(cipherText)
    bad[0] = (bad[0] as number) ^ 0xff
    // Hybrid/ML-KEM uses implicit rejection: decaps returns a pseudo-random
    // secret rather than throwing, so it must simply not match.
    const recovered = kem.decapsulate(bad, secretKey)
    expect(Buffer.from(recovered)).not.toEqual(Buffer.from(sharedSecret))
  })

  it('a different keypair cannot decapsulate', () => {
    const a = kem.keygen()
    const b = kem.keygen()
    const { cipherText, sharedSecret } = kem.encapsulate(a.publicKey)
    const recovered = kem.decapsulate(cipherText, b.secretKey)
    expect(Buffer.from(recovered)).not.toEqual(Buffer.from(sharedSecret))
  })
})

describe('pending KEM agility stubs', () => {
  it('HQC-256 is registered but throws NotImplementedError with a CONNECT pointer', () => {
    expect(() => getKem(KEM_IDS.HQC256)).toThrow(NotImplementedError)
    try {
      getKem(KEM_IDS.HQC256)
    } catch (e) {
      expect(e).toBeInstanceOf(NotImplementedError)
      expect((e as NotImplementedError).code).toBe('E_NOT_IMPLEMENTED')
      expect((e as NotImplementedError).connect).toMatch(/FIPS 207|HQC/)
    }
  })

  it('an unknown KEM id throws', () => {
    expect(() => getKem('NOPE')).toThrow(NotImplementedError)
  })
})
