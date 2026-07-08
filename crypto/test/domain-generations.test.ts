// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * ADR-0042 §c — cross-generation MUTUAL UNVERIFIABILITY, characterized cryptographically (not just
 * as string inequality). A message tagged under one generation must FAIL verification when the
 * verifier recomputes it under the other generation's tag: that is domain separation working as
 * designed, and it is exactly why the v2→v3 rename is a versioned protocol bump, never a
 * find-replace. Exercises one ML-DSA-87 space (ENVELOPE_SIGNED) and one HMAC-SHA-384 space
 * (PERMIT_MAC) as representatives. The v3 generation is INACTIVE (selector at v2) — these tests
 * construct v3 messages explicitly from DOMAIN_TAGS_V3; they change no emitted bytes.
 */

import { describe, it, expect } from 'vitest'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  DOMAIN_TAGS_V2,
  DOMAIN_TAGS_V3,
  encodeCanonical,
  HMAC_SHA384,
  signerFor,
  SUITE_IDS,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5
const signer = signerFor(suite)
const kp = signer.keygen(new Uint8Array(32).fill(7))
const BODY = { action: 'payments.transfer', amount: 42, nonce: 'gen-test' }

describe('ADR-0042 — cross-generation mutual unverifiability', () => {
  it('an ML-DSA-87 signature under the v3 envelope tag fails under the v2 tag (and vice versa)', () => {
    const v2Msg = encodeCanonical([DOMAIN_TAGS_V2.ENVELOPE_SIGNED, suite, BODY])
    const v3Msg = encodeCanonical([DOMAIN_TAGS_V3.ENVELOPE_SIGNED, suite, BODY])

    const v2Sig = signer.sign(v2Msg, kp.secretKey)
    const v3Sig = signer.sign(v3Msg, kp.secretKey)

    // Each generation verifies under ITSELF…
    expect(signer.verify(v2Sig, v2Msg, kp.publicKey)).toBe(true)
    expect(signer.verify(v3Sig, v3Msg, kp.publicKey)).toBe(true)
    // …and FAILS under the other (same key, same body — only the tag generation differs).
    expect(signer.verify(v2Sig, v3Msg, kp.publicKey)).toBe(false)
    expect(signer.verify(v3Sig, v2Msg, kp.publicKey)).toBe(false)
  })

  it('an HMAC-SHA-384 permit MAC under the v3 tag differs from the v2 tag (same key, same body)', () => {
    const key = new Uint8Array(48).fill(3)
    const mac = (tag: string) =>
      bytesToHex(HMAC_SHA384.compute(key, encodeCanonical([tag, suite, BODY])))

    const v2Mac = mac(DOMAIN_TAGS_V2.PERMIT_MAC)
    const v3Mac = mac(DOMAIN_TAGS_V3.PERMIT_MAC)

    // Different generations → different MACs under the SAME key and body: a v3 permit transcript
    // can never be replayed into a v2 verifier (or vice versa).
    expect(mac(DOMAIN_TAGS_V2.PERMIT_MAC)).toBe(v2Mac) // deterministic
    expect(v3Mac).not.toBe(v2Mac)
  })
})
