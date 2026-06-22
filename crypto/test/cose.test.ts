// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  signerFor,
  SUITE_IDS,
  encodeCanonical,
  coseSign1,
  coseSign1Verify,
  encodeCoseSign1,
  decodeCoseSign1,
  signEatResult,
  COSE_ALG,
} from '../src/index.js'

const SUITE = SUITE_IDS.PS_5
const s = signerFor(SUITE)
const enc = new TextEncoder()

describe('COSE_Sign1 (RFC 9052) over ML-DSA-87 (COSE alg -50, provisional)', () => {
  it('signs and verifies a payload', () => {
    const kp = s.keygen()
    const msg = coseSign1(enc.encode('hello'), SUITE, kp.secretKey, COSE_ALG.ML_DSA_87)
    expect(coseSign1Verify(msg, SUITE, kp.publicKey, COSE_ALG.ML_DSA_87)).toBe(true)
  })

  it('rejects wrong key, tampered payload, wrong alg, and wrong external_aad', () => {
    const kp = s.keygen()
    const aad = enc.encode('ctx')
    const msg = coseSign1(enc.encode('pay'), SUITE, kp.secretKey, COSE_ALG.ML_DSA_87, aad)
    expect(coseSign1Verify(msg, SUITE, kp.publicKey, COSE_ALG.ML_DSA_87, aad)).toBe(true)
    expect(coseSign1Verify(msg, SUITE, s.keygen().publicKey, COSE_ALG.ML_DSA_87, aad)).toBe(false)
    expect(
      coseSign1Verify(
        { ...msg, payload: enc.encode('PAY') },
        SUITE,
        kp.publicKey,
        COSE_ALG.ML_DSA_87,
        aad,
      ),
    ).toBe(false)
    // alg is in the signed protected header — asking for a different alg fails byte-exact
    expect(coseSign1Verify(msg, SUITE, kp.publicKey, COSE_ALG.ML_DSA_65, aad)).toBe(false)
    // external_aad is part of the signed Sig_structure — omitting it fails
    expect(coseSign1Verify(msg, SUITE, kp.publicKey, COSE_ALG.ML_DSA_87)).toBe(false)
  })

  it('round-trips the wire form and still verifies', () => {
    const kp = s.keygen()
    const msg = coseSign1(enc.encode('x'), SUITE, kp.secretKey, COSE_ALG.ML_DSA_87)
    const back = decodeCoseSign1(encodeCoseSign1(msg))
    expect(coseSign1Verify(back, SUITE, kp.publicKey, COSE_ALG.ML_DSA_87)).toBe(true)
  })

  it('signs a RATS/EAT attestation-result (nonce-bound) as COSE_Sign1', () => {
    const kp = s.keygen()
    const msg = signEatResult(
      enc.encode('nonce-123'),
      { eat_profile: 'polarseek-attestation', result: 'affirming' },
      SUITE,
      kp.secretKey,
    )
    expect(coseSign1Verify(msg, SUITE, kp.publicKey, COSE_ALG.ML_DSA_87)).toBe(true)
  })

  it('DECODE-TYPE-001: rejects a 4-element COSE whose fields are not byte strings (decode type-confusion)', () => {
    // A malformed COSE_Sign1 whose elements decode to wrong types must be rejected AT DECODE — never
    // cast `as Bytes` into verification, where coseSign1Verify's pre-try constantTimeEqual(msg.protected,
    // ...) would otherwise throw uncaught on a non-Uint8Array (round-3 decode-surface hardening).
    const malformed = encodeCanonical([123, new Map(), 'not-bytes', null])
    expect(() => decodeCoseSign1(malformed)).toThrow(/byte strings/)
    const wrongProtected = encodeCanonical([
      { a: 1 },
      new Map(),
      new Uint8Array([1]),
      new Uint8Array([2]),
    ])
    expect(() => decodeCoseSign1(wrongProtected)).toThrow()
    // sanity: a genuine COSE still decodes + verifies (no regression on the happy path)
    const kp = s.keygen()
    const ok = decodeCoseSign1(
      encodeCoseSign1(coseSign1(enc.encode('y'), SUITE, kp.secretKey, COSE_ALG.ML_DSA_87)),
    )
    expect(coseSign1Verify(ok, SUITE, kp.publicKey, COSE_ALG.ML_DSA_87)).toBe(true)
  })
})
