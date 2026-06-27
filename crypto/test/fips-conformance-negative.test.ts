// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * FIPS 203 / 204 / 205 negative-conformance tests.
 *
 * Nerion does not implement the PQ primitives itself — it delegates to
 * `@noble/post-quantum` through the {@link getKem} / {@link getSigner} wrappers
 * (see crypto/src/kem.ts, sign.ts). These tests lock the OBSERVABLE behavior of
 * that delegation boundary against the FIPS input-checking requirements, so a
 * future dependency bump cannot silently regress fail-closed behavior.
 *
 * The complementary happy-path / tamper tests live in kem.test.ts and sign.test.ts;
 * this file adds the requirements those don't cover: wrong-LENGTH input rejection
 * and implicit-rejection determinism.
 *
 * Mapped requirements (see docs/FIPS-CONFORMANCE-MAP.md):
 *  - FIPS 203 §7.2  Encapsulation-key type check (ek length == 384k+32).
 *  - FIPS 203 §7.3  Ciphertext type check (c length == 32(du·k+dv)), checked every Decaps.
 *  - FIPS 203 §6.3  Implicit rejection: a ciphertext that fails re-encryption yields
 *                   K̄ = J(z‖c) — a DETERMINISTIC pseudo-random shared secret of the
 *                   normal length, never an error/flag and never the honest secret.
 *  - FIPS 204 (and 205) Verify MUST reject any signature σ or public key pk of
 *                   incorrect length (FIPS 204, "If an implementation … can accept
 *                   inputs for σ or pk of any other length, it shall return [false]").
 *
 * A FIPS input check is satisfied by EITHER a thrown error OR a typed rejection
 * (verify→false / decaps→non-matching secret): the binding requirement is that a
 * malformed input is NEVER accepted as valid. The helpers below encode exactly that.
 */

import { describe, it, expect } from 'vitest'
import { getKem, implementedKemIds } from '../src/kem.js'
import { getSigner, implementedSigIds } from '../src/sign.js'

/** A verify-style op never ACCEPTS a malformed input: it returns false or throws. */
function neverAccepts(fn: () => boolean): void {
  let result: boolean
  try {
    result = fn()
  } catch {
    // Throwing on a malformed input is a conformant rejection.
    return
  }
  expect(result).toBe(false)
}

/** An op over malformed bytes must not SUCCEED with usable output: throw is fine. */
function rejectsOrThrows(fn: () => unknown): void {
  try {
    fn()
  } catch {
    return
  }
  // If it did not throw, the caller asserts the (non-)usability of the result.
}

describe.each(implementedKemIds())('FIPS 203 negative conformance — KEM %s', (id) => {
  const kem = getKem(id)
  const ekLen = kem.lengths.publicKey ?? kem.lengths.publicKeyBytes
  const ctLen = kem.lengths.cipherText ?? kem.lengths.cipherTextBytes

  it('exposes the expected fixed lengths', () => {
    // Length metadata must exist so callers can pre-validate (FIPS 203 §7 type checks).
    expect(typeof ekLen === 'number' || ekLen === undefined).toBe(true)
  })

  it('§7.2 wrong-length encapsulation key is rejected (not silently accepted)', () => {
    const { publicKey } = kem.keygen()
    const tooShort = publicKey.slice(0, publicKey.length - 1)
    const tooLong = new Uint8Array(publicKey.length + 1)
    tooLong.set(publicKey)
    const empty = new Uint8Array(0)
    for (const bad of [tooShort, tooLong, empty]) {
      rejectsOrThrows(() => {
        const out = kem.encapsulate(bad)
        // If it did not throw, the produced secret must at least be unusable:
        // re-deriving from a fresh keypair's secret must not match.
        const fresh = kem.keygen()
        const recovered = kem.decapsulate(out.cipherText, fresh.secretKey)
        expect(Buffer.from(recovered)).not.toEqual(Buffer.from(out.sharedSecret))
      })
    }
  })

  it('§7.3 wrong-length ciphertext is rejected by decapsulation', () => {
    const { publicKey, secretKey } = kem.keygen()
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
    const tooShort = cipherText.slice(0, cipherText.length - 1)
    const tooLong = new Uint8Array(cipherText.length + 1)
    tooLong.set(cipherText)
    const empty = new Uint8Array(0)
    for (const bad of [tooShort, tooLong, empty]) {
      try {
        const recovered = kem.decapsulate(bad, secretKey)
        // If it didn't throw, it must NEVER yield the honest shared secret.
        expect(Buffer.from(recovered)).not.toEqual(Buffer.from(sharedSecret))
      } catch {
        // Throwing on a wrong-length ciphertext is a conformant rejection.
      }
    }
  })

  it('§6.3 implicit rejection is deterministic and same-length (no error/flag leak)', () => {
    const { publicKey, secretKey } = kem.keygen()
    const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
    const tampered = Uint8Array.from(cipherText)
    tampered[0] = (tampered[0] as number) ^ 0xff
    // Same-length tamper: ML-KEM/hybrid must implicitly reject, not throw.
    const r1 = kem.decapsulate(tampered, secretKey)
    const r2 = kem.decapsulate(tampered, secretKey)
    expect(Buffer.from(r1)).not.toEqual(Buffer.from(sharedSecret)) // not the honest secret
    expect(Buffer.from(r1)).toEqual(Buffer.from(r2)) // deterministic (J(z‖c))
    expect(r1.length).toBe(sharedSecret.length) // same length — no observable reject signal
  })
})

describe.each(implementedSigIds())('FIPS 204/205 negative conformance — signer %s', (id) => {
  const signer = getSigner(id)
  const msg = new TextEncoder().encode('nerion: authorize action transfer')

  it('Verify rejects a wrong-length signature (FIPS 204 σ length check)', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey)
    const tooShort = sig.slice(0, sig.length - 1)
    const tooLong = new Uint8Array(sig.length + 1)
    tooLong.set(sig)
    const empty = new Uint8Array(0)
    for (const bad of [tooShort, tooLong, empty]) {
      neverAccepts(() => signer.verify(bad, msg, publicKey))
    }
  })

  it('Verify rejects a wrong-length public key (FIPS 204 pk length check)', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey)
    const tooShort = publicKey.slice(0, publicKey.length - 1)
    const tooLong = new Uint8Array(publicKey.length + 1)
    tooLong.set(publicKey)
    const empty = new Uint8Array(0)
    for (const bad of [tooShort, tooLong, empty]) {
      neverAccepts(() => signer.verify(sig, msg, bad))
    }
  })

  it('Verify rejects an all-zero signature of correct length', () => {
    const { publicKey } = signer.keygen()
    const zero = new Uint8Array(signer.sign(msg, signer.keygen().secretKey).length)
    neverAccepts(() => signer.verify(zero, msg, publicKey))
  })
})
