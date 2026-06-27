// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PQC-2 — hybrid-KEM combiner negative tests: the TRUNCATION / EXTENSION class.
 *
 * kem.test.ts already covers the 1-byte-tamper and wrong-key classes (implicit rejection). What was
 * NOT exercised is a LENGTH-ALTERING mutation of the hybrid ciphertext (dropping or appending bytes,
 * which can mis-split the classical/PQ legs of the combiner). This pins that class fail-closed:
 * decapsulating any truncated or extended ciphertext must NEVER recover the original shared secret —
 * it either throws (length mismatch) or yields a different (implicitly-rejected) secret. Plus a
 * regression sanity pin: the honest round-trip recovers and the combiner ciphertext length is stable
 * (so a future @noble bump that silently changes the combiner format is visible).
 *
 * Additive: tests only; no crypto behaviour, no wire / KAT / `Ps1` change. UNAUDITED.
 */

import { describe, it, expect } from 'vitest'
import fc from 'fast-check'
import { getKem, implementedKemIds } from '../src/kem.js'

const eq = (a: Uint8Array, b: Uint8Array): boolean => Buffer.from(a).equals(Buffer.from(b))

describe.each(implementedKemIds())(
  'PQC-2 — hybrid KEM %s truncation/extension fails closed',
  (id) => {
    const kem = getKem(id)

    /** Fail-closed predicate: a malformed ciphertext must NOT recover the original secret. */
    const recoversOriginal = (ct: Uint8Array, sk: Uint8Array, secret: Uint8Array): boolean => {
      try {
        return eq(kem.decapsulate(ct, sk), secret)
      } catch {
        return false // a thrown length/format error is fail-closed
      }
    }

    it('honest round-trip recovers; combiner ciphertext length is stable (regression pin)', () => {
      const { publicKey, secretKey } = kem.keygen()
      const a = kem.encapsulate(publicKey)
      const b = kem.encapsulate(publicKey)
      expect(recoversOriginal(a.cipherText, secretKey, a.sharedSecret)).toBe(true)
      expect(a.cipherText.length).toBe(b.cipherText.length)
      expect(a.cipherText.length).toBeGreaterThan(32)
    })

    it('explicit truncations never recover the shared secret', () => {
      const { publicKey, secretKey } = kem.keygen()
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
      const n = cipherText.length
      const cuts = [n - 1, Math.floor(n / 2), 32, 1, 0].filter((c) => c < n && c >= 0)
      for (const c of cuts) {
        expect(recoversOriginal(cipherText.slice(0, c), secretKey, sharedSecret)).toBe(false)
      }
      // dropping the FIRST byte (shifts both combiner legs) must also fail closed
      expect(recoversOriginal(cipherText.slice(1), secretKey, sharedSecret)).toBe(false)
    })

    it('explicit extensions never recover the shared secret', () => {
      const { publicKey, secretKey } = kem.keygen()
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
      const extend = (suffix: Uint8Array): Uint8Array => {
        const out = new Uint8Array(cipherText.length + suffix.length)
        out.set(cipherText)
        out.set(suffix, cipherText.length)
        return out
      }
      for (const suffix of [Uint8Array.of(0), Uint8Array.of(0xff), new Uint8Array(64)]) {
        expect(recoversOriginal(extend(suffix), secretKey, sharedSecret)).toBe(false)
      }
    })

    it('property: any length-altered ciphertext fails closed', () => {
      const { publicKey, secretKey } = kem.keygen()
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
      const n = cipherText.length
      fc.assert(
        fc.property(fc.integer({ min: 0, max: n + 64 }), (len) => {
          if (len === n) return // only test LENGTH-ALTERED ciphertexts
          let mutated: Uint8Array
          if (len < n) {
            mutated = cipherText.slice(0, len)
          } else {
            mutated = new Uint8Array(len)
            mutated.set(cipherText) // original prefix + zero-fill tail
          }
          expect(recoversOriginal(mutated, secretKey, sharedSecret)).toBe(false)
        }),
        { seed: 0x70716332, numRuns: 200 },
      )
    })
  },
)
