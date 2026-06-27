// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS, randomBytes } from '../../crypto/src/index.js'
import { SealingKeyProvider, sealedKeyAad, type SeedSealer, type SealedKey } from '../src/index.js'

/**
 * CUSTODY-SEAL-AAD-001 (FIX #6). `SealedKey.id/suite/sigId` are at-rest metadata
 * that the legacy seal did NOT bind into the wrap, so a blob legitimately sealed
 * under one id could be relabeled / swapped across keys sealed under the same KEK
 * and `load()` would unlock it under the new label. The fix routes a canonical
 * `id|suite|sigId` binding through the {@link SeedSealer} seam as Associated Data
 * (AAD), so an AEAD backend (AWS KMS EncryptionContext) rejects a mismatched
 * unwrap. These tests exercise the seam with a fake AEAD sealer that ENFORCES the
 * aad (real AEAD semantics), plus the backend-agnostic sigId metadata check.
 */
const suite = SUITE_IDS.PS_5
const scheme = signerFor(suite)
const MSG = new TextEncoder().encode('govern the verb, never the eye')

/**
 * A fake symmetric-AEAD sealer that faithfully ENFORCES aad: the aad used at
 * unwrap MUST byte-equal the aad used at wrap, else decryption "fails" — exactly
 * how AWS KMS EncryptionContext behaves. The blob carries the aad-tag so we can
 * detect a mismatch without real crypto.
 */
class AeadFakeSealer implements SeedSealer {
  private readonly mask = 0x5a
  async wrap(seed: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    const tag = aad ?? new Uint8Array(0)
    const ct = seed.map((b) => b ^ this.mask)
    // blob = [u32 tagLen][tag][ct]
    const out = new Uint8Array(4 + tag.length + ct.length)
    new DataView(out.buffer).setUint32(0, tag.length)
    out.set(tag, 4)
    out.set(ct, 4 + tag.length)
    return out
  }
  async unwrap(blob: Uint8Array, aad?: Uint8Array): Promise<Uint8Array> {
    const tagLen = new DataView(blob.buffer, blob.byteOffset, blob.byteLength).getUint32(0)
    const tag = blob.subarray(4, 4 + tagLen)
    const ct = blob.subarray(4 + tagLen)
    const want = aad ?? new Uint8Array(0)
    if (tag.length !== want.length || !tag.every((b, i) => b === want[i])) {
      throw new Error('AeadFakeSealer: AAD mismatch — decryption failed (relabel/cross-key swap)')
    }
    return ct.map((b) => b ^ this.mask)
  }
}

describe('CUSTODY-SEAL-AAD-001 — id/suite/sigId bound as AEAD AAD', () => {
  it('sealedKeyAad is deterministic and length-prefixed (no field-boundary collisions)', () => {
    const a = sealedKeyAad({ id: 'a', suite: 'bc', sigId: 'd' })
    const b = sealedKeyAad({ id: 'a', suite: 'bc', sigId: 'd' })
    expect(Array.from(a)).toEqual(Array.from(b))
    // "ab|c" vs "a|bc" must not collide: length prefixes separate them.
    const x = sealedKeyAad({ id: 'ab', suite: 'c', sigId: 'd' })
    const y = sealedKeyAad({ id: 'a', suite: 'bc', sigId: 'd' })
    expect(Array.from(x)).not.toEqual(Array.from(y))
  })

  it('genuine blob round-trips through the AEAD seam (provision + cold load)', async () => {
    const { sealed, publicKey } = await new SealingKeyProvider(
      new AeadFakeSealer(),
      'aead',
    ).provision(suite, 'issuer')
    const cold = new SealingKeyProvider(new AeadFakeSealer(), 'aead')
    const ref = await cold.load(sealed)
    expect(cold.getPublicKey(ref)).toEqual(publicKey)
    expect(signerFor(suite).verify(cold.sign(ref, suite, MSG), MSG, publicKey)).toBe(true)
  })

  it('THE FIX: a relabeled blob (id changed) fails to unwrap on an AEAD backend', async () => {
    const { sealed } = await new SealingKeyProvider(new AeadFakeSealer(), 'aead').provision(
      suite,
      'issuer-A',
    )
    // Attacker keeps the ciphertext but rewrites the unauthenticated id label.
    const relabeled: SealedKey = { ...sealed, id: 'victim-B' }
    const node = new SealingKeyProvider(new AeadFakeSealer(), 'aead')
    await expect(node.load(relabeled)).rejects.toThrow(/AAD mismatch|decryption failed/)
  })

  it('backend-agnostic: a relabeled sigId is rejected by the metadata check', async () => {
    const { sealed } = await new SealingKeyProvider(new AeadFakeSealer(), 'aead').provision(
      suite,
      'k',
    )
    const forgedSigId: SealedKey = { ...sealed, sigId: 'ML-DSA-44' }
    const node = new SealingKeyProvider(new AeadFakeSealer(), 'aead')
    await expect(node.load(forgedSigId)).rejects.toThrow(/metadata check/)
  })

  it('a corrupted ciphertext still fails (integrity preserved)', async () => {
    const { sealed } = await new SealingKeyProvider(new AeadFakeSealer(), 'aead').provision(
      suite,
      'k',
    )
    const corrupted: SealedKey = { ...sealed, wrappedSeed: Uint8Array.from(sealed.wrappedSeed) }
    // flip a byte inside the ciphertext region (after the [u32 len][tag] header)
    const i = corrupted.wrappedSeed.length - 1
    corrupted.wrappedSeed[i] = (corrupted.wrappedSeed[i] ?? 0) ^ 0xff
    const node = new SealingKeyProvider(new AeadFakeSealer(), 'aead')
    await expect(node.load(corrupted)).rejects.toThrow(/integrity check/)
  })

  it('legacy (aad-ignoring) backends still round-trip — AAD is optional', async () => {
    // A sealer that ignores aad entirely models a non-AEAD backend (Azure RSA-OAEP).
    const legacy: SeedSealer = {
      async wrap(seed) {
        return seed.map((b) => b ^ 0x3c)
      },
      async unwrap(blob) {
        return blob.map((b) => b ^ 0x3c)
      },
    }
    const { sealed, publicKey } = await new SealingKeyProvider(legacy, 'legacy').provision(
      suite,
      'k',
    )
    const cold = new SealingKeyProvider(
      {
        async wrap(seed) {
          return seed.map((b) => b ^ 0x3c)
        },
        async unwrap(blob) {
          return blob.map((b) => b ^ 0x3c)
        },
      },
      'legacy',
    )
    const ref = await cold.load(sealed)
    expect(cold.getPublicKey(ref)).toEqual(publicKey)
    // sanity: the canonical aad the provider would have used is well-formed
    expect(sealedKeyAad({ id: 'k', suite, sigId: scheme.id }).length).toBeGreaterThan(0)
    expect(randomBytes(1).length).toBe(1)
  })
})
