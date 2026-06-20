// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  AES_256_GCM,
  HMAC_SHA384,
  SHA3_SHAKE256,
  randomBytes,
  constantTimeEqual,
} from '../src/symmetric.js'
import { VerificationError } from '../src/errors.js'

describe('AES-256-GCM', () => {
  const key = randomBytes(32)
  const nonce = randomBytes(12)
  const pt = new TextEncoder().encode('permit: tier T2 step-up required')
  const aad = new TextEncoder().encode('suite=PS-5')

  it('seal then open round-trips', () => {
    const ct = AES_256_GCM.seal(key, nonce, pt, aad)
    const out = AES_256_GCM.open(key, nonce, ct, aad)
    expect(Buffer.from(out)).toEqual(Buffer.from(pt))
  })

  it('open throws VerificationError on a tampered ciphertext', () => {
    const ct = AES_256_GCM.seal(key, nonce, pt, aad)
    ct[0] = (ct[0] as number) ^ 0xff
    expect(() => AES_256_GCM.open(key, nonce, ct, aad)).toThrow(VerificationError)
  })

  it('open throws when AAD differs', () => {
    const ct = AES_256_GCM.seal(key, nonce, pt, aad)
    const wrongAad = new TextEncoder().encode('suite=PS-1')
    expect(() => AES_256_GCM.open(key, nonce, ct, wrongAad)).toThrow(VerificationError)
  })
})

describe('HMAC-SHA-384', () => {
  const key = randomBytes(32)
  const msg = new TextEncoder().encode('PolarSeek-Permit-v1')

  it('is deterministic and 48 bytes', () => {
    const a = HMAC_SHA384.compute(key, msg)
    const b = HMAC_SHA384.compute(key, msg)
    expect(a.length).toBe(48)
    expect(Buffer.from(a)).toEqual(Buffer.from(b))
  })

  it('verify accepts a valid tag and rejects tampering', () => {
    const tag = HMAC_SHA384.compute(key, msg)
    expect(HMAC_SHA384.verify(key, msg, tag)).toBe(true)
    tag[0] = (tag[0] as number) ^ 0x01
    expect(HMAC_SHA384.verify(key, msg, tag)).toBe(false)
  })

  it('verify rejects the wrong key', () => {
    const tag = HMAC_SHA384.compute(key, msg)
    expect(HMAC_SHA384.verify(randomBytes(32), msg, tag)).toBe(false)
  })
})

describe('SHA3-256 / SHAKE256', () => {
  it('digest is 32 bytes and stable', () => {
    const m = new TextEncoder().encode('commit me')
    expect(SHA3_SHAKE256.digest(m).length).toBe(32)
    expect(Buffer.from(SHA3_SHAKE256.digest(m))).toEqual(Buffer.from(SHA3_SHAKE256.digest(m)))
  })
  it('xof produces the requested length', () => {
    const m = new TextEncoder().encode('expand me')
    expect(SHA3_SHAKE256.xof(m, 64).length).toBe(64)
    expect(SHA3_SHAKE256.xof(m, 17).length).toBe(17)
  })
})

describe('constantTimeEqual', () => {
  it('matches equal arrays and rejects unequal length/content', () => {
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3]))).toBe(true)
    expect(constantTimeEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 4]))).toBe(false)
    expect(constantTimeEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toBe(false)
  })
})
