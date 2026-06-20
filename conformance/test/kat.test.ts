// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { readFileSync } from 'node:fs'
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import {
  SHA3_SHAKE256,
  HMAC_SHA384,
  AES_256_GCM,
  encodeCanonical,
  getSigner,
  getKem,
  implementedKemIds,
} from '../../crypto/src/index.js'

/**
 * Frozen Known-Answer Tests. The committed vectors (conformance/vectors/ps-kat.json,
 * produced by `npm run kat`) are the byte-exact contract; this test proves the
 * live reference implementation still reproduces them. A diff here means either a
 * real regression or an intentional change that must be re-frozen on purpose.
 */
interface Kat {
  version: string
  hash: {
    sha3_256: { msgUtf8: string; digestHex: string }[]
    shake256: { msgUtf8: string; outLen: number; outHex: string }[]
  }
  mac: { hmac_sha384: { keyHex: string; msgUtf8: string; tagHex: string }[] }
  aead: {
    aes_256_gcm: {
      keyHex: string
      nonceHex: string
      aadHex: string
      ptHex: string
      ctHex: string
    }[]
  }
  sig: Record<
    string,
    {
      seedHex: string
      publicKeyLen: number
      secretKeyLen: number
      publicKeySha3: string
      secretKeySha3: string
    }
  >
  cbor: { label: string; value: unknown; hex: string }[]
}

const kat = JSON.parse(
  readFileSync(new URL('../vectors/ps-kat.json', import.meta.url), 'utf8'),
) as Kat
const enc = (s: string): Uint8Array => new TextEncoder().encode(s)

describe('PolarSeek KAT vectors', () => {
  it('is the expected vector set version', () => {
    expect(kat.version).toBe('PS-KAT-1')
  })

  it('SHA3-256 reproduces every pinned digest', () => {
    for (const v of kat.hash.sha3_256) {
      expect(bytesToHex(SHA3_SHAKE256.digest(enc(v.msgUtf8)))).toBe(v.digestHex)
    }
  })

  it('SHAKE256 reproduces every pinned XOF output', () => {
    for (const v of kat.hash.shake256) {
      expect(bytesToHex(SHA3_SHAKE256.xof(enc(v.msgUtf8), v.outLen))).toBe(v.outHex)
    }
  })

  it('HMAC-SHA-384 reproduces every pinned tag', () => {
    for (const v of kat.mac.hmac_sha384) {
      expect(bytesToHex(HMAC_SHA384.compute(hexToBytes(v.keyHex), enc(v.msgUtf8)))).toBe(v.tagHex)
    }
  })

  it('AES-256-GCM reproduces ciphertext and round-trips', () => {
    for (const v of kat.aead.aes_256_gcm) {
      const key = hexToBytes(v.keyHex)
      const nonce = hexToBytes(v.nonceHex)
      const aad = hexToBytes(v.aadHex)
      const pt = hexToBytes(v.ptHex)
      const ct = AES_256_GCM.seal(key, nonce, pt, aad)
      expect(bytesToHex(ct)).toBe(v.ctHex)
      expect(bytesToHex(AES_256_GCM.open(key, nonce, ct, aad))).toBe(v.ptHex)
    }
  })

  it('signature keygen-from-seed is deterministic for every pinned scheme', () => {
    for (const [sigId, v] of Object.entries(kat.sig)) {
      const kp = getSigner(sigId).keygen(hexToBytes(v.seedHex))
      expect(kp.publicKey.length).toBe(v.publicKeyLen)
      expect(kp.secretKey.length).toBe(v.secretKeyLen)
      expect(bytesToHex(SHA3_SHAKE256.digest(kp.publicKey))).toBe(v.publicKeySha3)
      expect(bytesToHex(SHA3_SHAKE256.digest(kp.secretKey))).toBe(v.secretKeySha3)
    }
  })

  it('dCBOR reproduces every pinned canonical encoding', () => {
    for (const v of kat.cbor) {
      expect(bytesToHex(encodeCanonical(v.value))).toBe(v.hex)
    }
  })

  // ── property checks for the randomized operations (not byte-pinned) ──────────

  it('ML-DSA-87 sign/verify holds for the pinned key (and rejects tampering)', () => {
    const v = kat.sig['ML-DSA-87']
    expect(v).toBeDefined()
    const signer = getSigner('ML-DSA-87')
    const kp = signer.keygen(hexToBytes(v!.seedHex))
    const msg = enc('admit:payment.transfer')
    const sig = signer.sign(msg, kp.secretKey)
    expect(signer.verify(sig, msg, kp.publicKey)).toBe(true)
    expect(signer.verify(sig, enc('admit:payment.transferX'), kp.publicKey)).toBe(false)
  })

  it('every implemented hybrid KEM round-trips (encapsulate → decapsulate)', () => {
    for (const id of implementedKemIds()) {
      const kem = getKem(id)
      const { publicKey, secretKey } = kem.keygen()
      const { cipherText, sharedSecret } = kem.encapsulate(publicKey)
      expect(bytesToHex(kem.decapsulate(cipherText, secretKey))).toBe(bytesToHex(sharedSecret))
    }
  })
})
