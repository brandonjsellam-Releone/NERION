// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from 'vitest'
import { signerFor, SUITE_IDS, randomBytes } from '../../crypto/src/index.js'
import { SealingKeyProvider, type SeedSealer, type SealedKey } from '../src/index.js'

/**
 * CUSTODY-SEAL-001 (Team Apex, 2026-06-21). A `SealedKey` blob is "safe to
 * persist/replicate" and `load()` re-derives the public key and compares it to the
 * blob's OWN `publicKey` field — a self-referential check. Under a PUBLIC-KEY wrap
 * (Azure RSA-OAEP), an attacker who knows the public KEK can craft a wrapped seed
 * OFFLINE and set `publicKey` to match, substituting a chosen signing key under any
 * id; the self-check cannot detect it. The fix: `load(sealed, { trustedPublicKey })`
 * checks the re-derived key against an out-of-band-trusted key, breaking the
 * self-reference. (AWS symmetric AEAD wrap is not exposed to the offline variant.)
 */
const suite = SUITE_IDS.PS_5
const scheme = signerFor(suite)

// A PUBLIC-KEY-style sealer: wrap needs NO secret (identity here), modeling Azure
// RSA-OAEP where an attacker holds the public KEK — the exact CUSTODY-SEAL-001 condition.
const publicWrapSealer: SeedSealer = {
  async wrap(seed: Uint8Array) {
    return Uint8Array.from(seed)
  },
  async unwrap(blob: Uint8Array) {
    return Uint8Array.from(blob)
  },
}

function forgeBlob(legit: SealedKey): { forged: SealedKey; attackerPk: Uint8Array } {
  const attackerSeed = randomBytes(scheme.lengths.seed as number)
  const attackerKp = scheme.keygen(attackerSeed)
  const forged: SealedKey = {
    id: legit.id,
    suite: legit.suite,
    sigId: legit.sigId,
    // Attacker computes this offline (public-key wrap) — no backend permission needed.
    wrappedSeed: Uint8Array.from(attackerSeed),
    publicKey: attackerKp.publicKey, // set to match the re-derived key -> self-check passes
  }
  return { forged, attackerPk: attackerKp.publicKey }
}

describe('CUSTODY-SEAL-001 — sealed-blob substitution under a public-key wrap', () => {
  it('the VECTOR: a consistent forged blob passes load() when no trusted key is supplied', async () => {
    const { sealed: legit, publicKey: victimPk } = await new SealingKeyProvider(
      publicWrapSealer,
      'pub-kms',
    ).provision(suite, 'issuer')
    const { forged, attackerPk } = forgeBlob(legit)

    const node = new SealingKeyProvider(publicWrapSealer, 'pub-kms')
    const ref = await node.load(forged) // accepted — the documented gap
    expect(Array.from(node.getPublicKey(ref))).toEqual(Array.from(attackerPk))
    expect(Array.from(node.getPublicKey(ref))).not.toEqual(Array.from(victimPk))
  })

  it('the FIX: load() with the out-of-band trustedPublicKey rejects the substituted blob', async () => {
    const { sealed: legit, publicKey: victimPk } = await new SealingKeyProvider(
      publicWrapSealer,
      'pub-kms',
    ).provision(suite, 'issuer')
    const { forged } = forgeBlob(legit)

    const node = new SealingKeyProvider(publicWrapSealer, 'pub-kms')
    await expect(node.load(forged, { trustedPublicKey: victimPk })).rejects.toThrow(
      /CUSTODY-SEAL-001|authenticity/,
    )
    // the genuine blob still loads under the same trusted key
    const ref = await node.load(legit, { trustedPublicKey: victimPk })
    expect(Array.from(node.getPublicKey(ref))).toEqual(Array.from(victimPk))
  })

  it('still rejects an inconsistent (corrupted) blob via the self-check', async () => {
    const sealer = publicWrapSealer
    const { sealed } = await new SealingKeyProvider(sealer, 'pub-kms').provision(suite, 'k')
    const corrupted: SealedKey = { ...sealed, wrappedSeed: Uint8Array.from(sealed.wrappedSeed) }
    corrupted.wrappedSeed[0] = (corrupted.wrappedSeed[0] ?? 0) ^ 0xff
    await expect(new SealingKeyProvider(sealer, 'pub-kms').load(corrupted)).rejects.toThrow(
      /integrity check/,
    )
  })
})
