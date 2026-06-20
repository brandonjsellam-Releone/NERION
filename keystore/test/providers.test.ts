// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import {
  SUITE_IDS,
  verifyEnvelope,
  openEnvelope,
  NotImplementedError,
} from '../../crypto/src/index.js'
import {
  SoftwareKeyProvider,
  CloudKmsKeyProvider,
  KeyProviderRegistry,
  signEnvelopeViaProvider,
} from '../src/index.js'

const suite = SUITE_IDS.PS_5

describe('software key provider', () => {
  it('generates a key and signs an envelope verifiable by its public key', () => {
    const kp = new SoftwareKeyProvider()
    const { ref, publicKey } = kp.generate(suite, 'issuer-1')
    const payload = { intent: 'deploy', tier: 2 }
    const env = signEnvelopeViaProvider(payload, suite, kp, ref, 'receipt')
    expect(verifyEnvelope(env, publicKey)).toBe(true)
    expect(openEnvelope(env)).toEqual(payload)
  })

  it('exposes the same public key it signs under', () => {
    const kp = new SoftwareKeyProvider()
    const { ref, publicKey } = kp.generate(suite, 'k')
    expect(Buffer.from(kp.getPublicKey(ref))).toEqual(Buffer.from(publicKey))
  })

  it('throws for an unknown key id', () => {
    const kp = new SoftwareKeyProvider()
    expect(() => kp.getPublicKey({ provider: 'software', id: 'nope' })).toThrow()
  })
})

describe('cloud-KMS provider stub (AWS / GCP)', () => {
  it('Cloud KMS fails loudly with a CONNECT pointer', () => {
    expect(() =>
      new CloudKmsKeyProvider().getPublicKey({ provider: 'cloud-kms', id: 'k' }),
    ).toThrow(NotImplementedError)
  })
})

describe('provider registry', () => {
  it('routes signing to the provider named in the ref', () => {
    const sw = new SoftwareKeyProvider()
    const { ref, publicKey } = sw.generate(suite, 'reg-key')
    const registry = new KeyProviderRegistry().register(sw).register(new CloudKmsKeyProvider())
    const env = signEnvelopeViaProvider({ x: 1 }, suite, sw, ref)
    expect(verifyEnvelope(env, publicKey)).toBe(true)
    // Registry resolves the public key by ref.
    expect(Buffer.from(registry.getPublicKey(ref))).toEqual(Buffer.from(publicKey))
  })

  it('throws for an unregistered provider', () => {
    const registry = new KeyProviderRegistry()
    expect(() => registry.getPublicKey({ provider: 'ghost', id: 'k' })).toThrow()
  })
})
