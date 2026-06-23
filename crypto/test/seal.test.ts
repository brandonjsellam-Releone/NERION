// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { sealToKem, openSealed, getKem, implementedKemIds } from '../src/index.js'
import type { SealParams } from '../src/index.js'

/**
 * Hybrid-KEM sealing (ADR-0028) — confidentiality + the KDF context-binding matrix. The working AEAD
 * key is HKDF-bound to {suite, KEM-id, ciphertext, senderId, recipientId}, so altering ANY of them
 * derives a different key and the GCM tag must fail (fail closed). Exercised across every implemented
 * hybrid KEM.
 */
const enc = new TextEncoder()
const PT = enc.encode('govern the verb, never the eye — secret payload')
const SUITE = 'PS-5'

describe.each(implementedKemIds())('hybrid-KEM sealing (ADR-0028) — %s', (kemId) => {
  const kem = getKem(kemId)
  const params = (recipientId: string): SealParams => ({
    suite: SUITE,
    kemId,
    senderId: 'sender-1',
    recipientId,
  })

  it('seal → open round-trips the plaintext for the intended recipient', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    const opened = openSealed(sealed, r, { suite: SUITE, recipientId: 'recip-1' })
    expect(Buffer.from(opened)).toEqual(Buffer.from(PT))
  })

  it('a different recipient key cannot open (KEM confidentiality)', () => {
    const r = kem.keygen()
    const other = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    expect(() => openSealed(sealed, other, { suite: SUITE, recipientId: 'recip-1' })).toThrow()
  })

  it('a tampered KEM ciphertext fails closed', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    const kemCiphertext = Uint8Array.from(sealed.kemCiphertext)
    kemCiphertext[0] = (kemCiphertext[0] as number) ^ 0xff
    expect(() =>
      openSealed({ ...sealed, kemCiphertext }, r, {
        suite: SUITE,
        recipientId: 'recip-1',
      }),
    ).toThrow()
  })

  it('a tampered AEAD ciphertext fails the tag', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    const ciphertext = Uint8Array.from(sealed.ciphertext)
    ciphertext[0] = (ciphertext[0] as number) ^ 0xff
    expect(() =>
      openSealed({ ...sealed, ciphertext }, r, { suite: SUITE, recipientId: 'recip-1' }),
    ).toThrow()
  })

  it('ADR-0028: a swapped suite is rejected (cross-suite downgrade)', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    // relying party expects a different suite → fail closed before crypto
    expect(() => openSealed(sealed, r, { suite: 'PS-1', recipientId: 'recip-1' })).toThrow(/suite/)
    // forging the header field too → KDF info mismatch → tag fails
    expect(() =>
      openSealed({ ...sealed, suite: 'PS-1' }, r, {
        suite: 'PS-1',
        recipientId: 'recip-1',
      }),
    ).toThrow()
  })

  it('ADR-0028: a swapped recipientId is rejected (mis-addressed / unknown-key-share)', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    expect(() => openSealed(sealed, r, { suite: SUITE, recipientId: 'recip-2' })).toThrow(
      /recipient/,
    )
    expect(() =>
      openSealed({ ...sealed, recipientId: 'recip-2' }, r, {
        suite: SUITE,
        recipientId: 'recip-2',
      }),
    ).toThrow()
  })

  it('ADR-0028: a swapped senderId is rejected (bound via the KDF, not just transmitted)', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    expect(() =>
      openSealed({ ...sealed, senderId: 'attacker' }, r, {
        suite: SUITE,
        recipientId: 'recip-1',
      }),
    ).toThrow()
  })

  it('fresh nonce per seal → two seals of identical plaintext differ (no nonce reuse)', () => {
    const r = kem.keygen()
    const a = sealToKem(r.publicKey, PT, params('recip-1'))
    const b = sealToKem(r.publicKey, PT, params('recip-1'))
    expect(Buffer.from(a.nonce)).not.toEqual(Buffer.from(b.nonce))
    expect(Buffer.from(a.ciphertext)).not.toEqual(Buffer.from(b.ciphertext))
  })
})
