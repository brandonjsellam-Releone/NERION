// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS, NotImplementedError } from '../../crypto/src/index.js'
import { Pkcs11KeyProvider, Pkcs11Sealer, pkcs11SealerFromEnv } from '../src/index.js'
import type { Pkcs11WrapEngine } from '../src/index.js'

/** Fake PKCS#11 token engine: a faithful, byte-transforming wrap/unwrap. */
class FakeEngine implements Pkcs11WrapEngine {
  wraps = 0
  unwraps = 0
  private readonly mask = 0x3c
  async wrap(seed: Uint8Array): Promise<Uint8Array> {
    this.wraps++
    return seed.map((b) => b ^ this.mask)
  }
  async unwrap(blob: Uint8Array): Promise<Uint8Array> {
    this.unwraps++
    return blob.map((b) => b ^ this.mask)
  }
}

const suite = SUITE_IDS.PS_5
const MSG = new TextEncoder().encode('seal the verb in the HSM')

describe('Pkcs11KeyProvider (HSM-as-sealing-KEK, model B)', () => {
  it('provisions, seals the seed via the token, and signs verifiably', async () => {
    const engine = new FakeEngine()
    const p = new Pkcs11KeyProvider(new Pkcs11Sealer(engine))
    const { ref, publicKey, sealed } = await p.provision(suite, 'root')
    expect(engine.wraps).toBe(1)
    expect(ref.provider).toBe('pkcs11')
    expect(signerFor(suite).verify(p.sign(ref, suite, MSG), MSG, publicKey)).toBe(true)
    expect(sealed.wrappedSeed.length).toBe(32)
  })

  it('a cold provider can load() the sealed key and reproduce the SAME keypair', async () => {
    const { sealed, publicKey } = await new Pkcs11KeyProvider(
      new Pkcs11Sealer(new FakeEngine()),
    ).provision(suite, 'k')
    const coldEngine = new FakeEngine()
    // Pkcs11Sealer defaults isPublicKeyWrap:true (CUSTODY-SEAL-002) so trustedPublicKey is
    // required — modeled here as the value provision() returned, kept out-of-band-trusted.
    const cold = new Pkcs11KeyProvider(new Pkcs11Sealer(coldEngine))
    const ref = await cold.load(sealed, { trustedPublicKey: publicKey })
    expect(coldEngine.unwraps).toBe(1) // load does exactly one unwrap
    expect(cold.getPublicKey(ref)).toEqual(publicKey)
    expect(signerFor(suite).verify(cold.sign(ref, suite, MSG), MSG, publicKey)).toBe(true)
  })

  it('CUSTODY-SEAL-002: fails closed without trustedPublicKey when isPublicKeyWrap defaults true', async () => {
    const { sealed } = await new Pkcs11KeyProvider(new Pkcs11Sealer(new FakeEngine())).provision(
      suite,
      'k2',
    )
    const cold = new Pkcs11KeyProvider(new Pkcs11Sealer(new FakeEngine()))
    await expect(cold.load(sealed)).rejects.toThrow(
      /CUSTODY-SEAL-002|requires opts\.trustedPublicKey/,
    )
  })

  it('an engine known to be symmetric-AEAD can opt out via isPublicKeyWrap:false', async () => {
    const { sealed, publicKey } = await new Pkcs11KeyProvider(
      new Pkcs11Sealer(new FakeEngine(), false),
    ).provision(suite, 'k3')
    const cold = new Pkcs11KeyProvider(new Pkcs11Sealer(new FakeEngine(), false))
    const ref = await cold.load(sealed) // no trustedPublicKey needed — opted out
    expect(cold.getPublicKey(ref)).toEqual(publicKey)
  })

  it('refuses to sign before unlock', () => {
    const p = new Pkcs11KeyProvider(new Pkcs11Sealer(new FakeEngine()))
    expect(() => p.sign({ provider: 'pkcs11', id: 'x' }, suite, MSG)).toThrow(/not unlocked/)
  })

  it('sign() rejects a mismatched suite', async () => {
    const p = new Pkcs11KeyProvider(new Pkcs11Sealer(new FakeEngine()))
    const { ref } = await p.provision(suite, 'k')
    expect(() => p.sign(ref, SUITE_IDS.PS_1, MSG)).toThrow(/is suite .* not/)
  })
})

describe('pkcs11SealerFromEnv', () => {
  it('requires PKCS11_MODULE_PATH and PKCS11_PIN', () => {
    expect(() => pkcs11SealerFromEnv({}, () => new FakeEngine())).toThrow(/must both be set/)
    expect(() =>
      pkcs11SealerFromEnv({ PKCS11_MODULE_PATH: '/x.so' }, () => new FakeEngine()),
    ).toThrow(/must both be set/)
  })

  it('demands a native engine factory rather than faking a connection', () => {
    expect(() =>
      pkcs11SealerFromEnv({ PKCS11_MODULE_PATH: '/usr/lib/libsofthsm2.so', PKCS11_PIN: '1234' }),
    ).toThrow(NotImplementedError)
  })

  it('builds a sealer (passing config through) when an engine factory is supplied', async () => {
    const sealer = pkcs11SealerFromEnv(
      {
        PKCS11_MODULE_PATH: '/usr/lib/libsofthsm2.so',
        PKCS11_PIN: '1234',
        PKCS11_WRAP_KEY_LABEL: 'polarseek-kek',
      },
      (cfg) => {
        expect(cfg.modulePath).toBe('/usr/lib/libsofthsm2.so')
        expect(cfg.pin).toBe('1234')
        expect(cfg.wrapKeyLabel).toBe('polarseek-kek')
        return new FakeEngine()
      },
    )
    const wrapped = await sealer.wrap(new Uint8Array([1, 2, 3]))
    expect(Array.from(await sealer.unwrap(wrapped))).toEqual([1, 2, 3])
  })
})
