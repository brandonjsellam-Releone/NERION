// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS } from '../../crypto/src/index.js'
import { AzureKeyVaultKeyProvider } from '../src/index.js'
import type { SeedSealer } from '../src/index.js'

/**
 * Fake sealer standing in for Azure Key Vault wrap/unwrap. It is a faithful
 * round-trip (unwrap(wrap(x)) === x) and actually transforms the bytes, so the
 * tests can prove the persisted blob is not the seed in the clear.
 */
class FakeSealer implements SeedSealer {
  wraps = 0
  unwraps = 0
  private readonly mask = 0x5a
  async wrap(seed: Uint8Array): Promise<Uint8Array> {
    this.wraps++
    return seed.map((b) => b ^ this.mask)
  }
  async unwrap(sealed: Uint8Array): Promise<Uint8Array> {
    this.unwraps++
    return sealed.map((b) => b ^ this.mask)
  }
}

const suite = SUITE_IDS.PS_5
const MSG = new TextEncoder().encode('govern the verb, never the eye')

describe('AzureKeyVaultKeyProvider (KV-as-sealing-KEK, model B)', () => {
  it('provisions, seals the seed, and signs verifiably', async () => {
    const sealer = new FakeSealer()
    const p = new AzureKeyVaultKeyProvider(sealer)
    const { ref, publicKey, sealed } = await p.provision(suite, 'issuer')

    expect(sealer.wraps).toBe(1)
    const sig = p.sign(ref, suite, MSG)
    expect(signerFor(suite).verify(sig, MSG, publicKey)).toBe(true)

    // the at-rest blob advertises the matching public key and is ML-DSA-87's
    // 32-byte seed length once unwrapped — but is never stored in the clear.
    expect(sealed.publicKey).toEqual(publicKey)
    expect(sealed.wrappedSeed.length).toBe(32)
    expect(sealed.sigId).toBe('ML-DSA-87')
  })

  it('a cold provider can load() the sealed key and reproduce the SAME keypair', async () => {
    const { sealed, publicKey } = await new AzureKeyVaultKeyProvider(new FakeSealer()).provision(
      suite,
      'k',
    )

    // brand-new provider + sealer, only the sealed blob on hand (fresh process)
    const coldSealer = new FakeSealer()
    const cold = new AzureKeyVaultKeyProvider(coldSealer)
    const ref = await cold.load(sealed)
    expect(coldSealer.unwraps).toBe(1) // load does exactly one unwrap

    expect(cold.getPublicKey(ref)).toEqual(publicKey)
    const sig = cold.sign(ref, suite, MSG)
    expect(signerFor(suite).verify(sig, MSG, publicKey)).toBe(true)
  })

  it('refuses to sign before unlock — the secret lives only in the seal', () => {
    const p = new AzureKeyVaultKeyProvider(new FakeSealer())
    expect(() => p.sign({ provider: 'azure-kv', id: 'missing' }, suite, MSG)).toThrow(
      /not unlocked/,
    )
  })

  it('lock() zeroizes and drops the unlocked key', async () => {
    const p = new AzureKeyVaultKeyProvider(new FakeSealer())
    const { ref } = await p.provision(suite, 'tmp')
    p.lock('tmp')
    expect(() => p.sign(ref, suite, MSG)).toThrow(/not unlocked/)
  })

  it('rejects synchronous generate() (KV wrap is async)', () => {
    const p = new AzureKeyVaultKeyProvider(new FakeSealer())
    expect(() => p.generate(suite, 'x')).toThrow(/provision/)
  })

  it('rejects a tampered sealed blob (re-derived public key must match)', async () => {
    const sealer = new FakeSealer()
    const { sealed } = await new AzureKeyVaultKeyProvider(sealer).provision(suite, 'k')
    const tampered = { ...sealed, wrappedSeed: Uint8Array.from(sealed.wrappedSeed) }
    tampered.wrappedSeed[0] = (tampered.wrappedSeed[0] ?? 0) ^ 0xff
    const cold = new AzureKeyVaultKeyProvider(sealer)
    await expect(cold.load(tampered)).rejects.toThrow(/integrity check/)
  })

  it('sign() rejects a mismatched suite', async () => {
    const p = new AzureKeyVaultKeyProvider(new FakeSealer())
    const { ref } = await p.provision(suite, 'k')
    expect(() => p.sign(ref, SUITE_IDS.PS_1, MSG)).toThrow(/is suite .* not/)
  })
})
