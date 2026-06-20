// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { getSigner, implementedSigIds, SIG_IDS } from '../src/sign.js'
import { NotImplementedError } from '../src/errors.js'

const msg = new TextEncoder().encode('action: transfer 5 USDC to alice')

describe.each(implementedSigIds())('signature scheme %s', (id) => {
  const signer = getSigner(id)

  it('sign then verify succeeds', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey)
    expect(signer.verify(sig, msg, publicKey)).toBe(true)
  })

  it('verify rejects a tampered message', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey)
    const altered = Uint8Array.from(msg)
    altered[0] = (altered[0] as number) ^ 0x01
    expect(signer.verify(sig, altered, publicKey)).toBe(false)
  })

  it('verify rejects a tampered signature', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey)
    sig[0] = (sig[0] as number) ^ 0x01
    expect(signer.verify(sig, msg, publicKey)).toBe(false)
  })

  it('verify rejects the wrong public key', () => {
    const a = signer.keygen()
    const b = signer.keygen()
    const sig = signer.sign(msg, a.secretKey)
    expect(signer.verify(sig, msg, b.publicKey)).toBe(false)
  })
})

describe('pending signature agility stubs', () => {
  it('FN-DSA-1024 (Falcon) is registered but not load-bearing', () => {
    expect(() => getSigner(SIG_IDS.FN_DSA_1024)).toThrow(NotImplementedError)
    try {
      getSigner(SIG_IDS.FN_DSA_1024)
    } catch (e) {
      expect((e as NotImplementedError).connect).toMatch(/FIPS 206/)
    }
  })
})
