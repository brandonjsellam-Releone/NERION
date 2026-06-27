// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PQC-4 — key-committing seal. AES-256-GCM is not key-committing, so a partitioning oracle could craft
 * one ciphertext that AEAD-verifies under two different derived keys. `sealToKem` now emits a
 * domain-separated `keyCommitment` over the shared secret + bound context, and `openSealed`
 * constant-time verifies it before the AEAD open — binding each ciphertext to exactly one (key,context).
 */

import { describe, it, expect } from 'vitest'
import { sealToKem, openSealed, getKem, implementedKemIds } from '../src/index.js'
import type { SealParams } from '../src/index.js'

const PT = new TextEncoder().encode('govern the verb, never the eye — committing seal')
const SUITE = 'PS-5'

describe.each(implementedKemIds())('PQC-4 — key-committing seal — %s', (kemId) => {
  const kem = getKem(kemId)
  const params = (recipientId: string): SealParams => ({
    suite: SUITE,
    kemId,
    senderId: 'sender-1',
    recipientId,
  })
  const expected = { suite: SUITE, recipientId: 'recip-1' }

  it('a valid seal carries a 32-byte key-commitment and round-trips', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    expect(sealed.keyCommitment.length).toBe(32)
    expect(Buffer.from(openSealed(sealed, r, expected))).toEqual(Buffer.from(PT))
  })

  it('a tampered key-commitment fails closed with the commitment error (checked before the AEAD)', () => {
    const r = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    const keyCommitment = Uint8Array.from(sealed.keyCommitment)
    keyCommitment[0] = (keyCommitment[0] as number) ^ 0xff
    expect(() => openSealed({ ...sealed, keyCommitment }, r, expected)).toThrow(
      /key-commitment mismatch/,
    )
  })

  it('a commitment grafted from a DIFFERENT seal is rejected (binds this exact key+context)', () => {
    const r = kem.keygen()
    const a = sealToKem(r.publicKey, PT, params('recip-1'))
    const b = sealToKem(r.publicKey, PT, params('recip-1')) // fresh KEM ct → different secret → different key → different commitment
    expect(Buffer.from(a.keyCommitment)).not.toEqual(Buffer.from(b.keyCommitment))
    // Splicing b's commitment onto a must fail: a's own derived key re-derives a's commitment, not b's.
    expect(() => openSealed({ ...a, keyCommitment: b.keyCommitment }, r, expected)).toThrow(
      /key-commitment mismatch/,
    )
  })

  it('a different recipient key cannot open — commitment + KEM both bind to one key', () => {
    const r = kem.keygen()
    const other = kem.keygen()
    const sealed = sealToKem(r.publicKey, PT, params('recip-1'))
    expect(() => openSealed(sealed, other, expected)).toThrow()
  })
})
