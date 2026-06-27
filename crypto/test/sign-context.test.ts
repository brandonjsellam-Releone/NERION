// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { getSigner, implementedSigIds } from '../src/sign.js'

/**
 * FIPS 204 / 205 context-string domain separation (closes the documented gap in
 * docs/FIPS-CONFORMANCE-MAP.md). The signer now accepts an optional `context`:
 *  - a context-bound signature verifies ONLY under the same context;
 *  - omitting the context uses the empty-context default — byte-identical to the
 *    prior 2-arg behaviour, so pinned no-context KATs are unaffected.
 */

const enc = (s: string): Uint8Array => new TextEncoder().encode(s)
const msg = enc('action: transfer 5 USDC to vendor-acme')
const PERMIT = enc('nerion:permit:v1')
const RECEIPT = enc('nerion:receipt:v1')

describe.each(implementedSigIds())('FIPS-204/205 context domain separation — %s', (id) => {
  const signer = getSigner(id)

  it('a context-bound signature verifies under the same context', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey, PERMIT)
    expect(signer.verify(sig, msg, publicKey, PERMIT)).toBe(true)
  })

  it('does NOT verify under a different context (domain separation)', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey, PERMIT)
    expect(signer.verify(sig, msg, publicKey, RECEIPT)).toBe(false)
    // ...nor under the empty/default context.
    expect(signer.verify(sig, msg, publicKey)).toBe(false)
  })

  it('no-context (default) sign/verify is unchanged; empty context == default', () => {
    const { publicKey, secretKey } = signer.keygen()
    const sig = signer.sign(msg, secretKey)
    expect(signer.verify(sig, msg, publicKey)).toBe(true)
    // An explicit empty context is the FIPS default — must accept the no-context sig.
    expect(signer.verify(sig, msg, publicKey, new Uint8Array(0))).toBe(true)
  })
})
