// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Hybrid-KEM sealing — confidentiality for a message addressed to a KEM public key (ADR-0028).
 *
 * `sealToKem` encapsulates to the recipient's hybrid-KEM public key, derives an AES-256-GCM key from
 * the shared secret via HKDF-SHA-384 whose `info` binds {label, version, SuiteID, KEM-id,
 * kemCiphertext, senderId, recipientId} as canonical CBOR (ADR-0028), and AEAD-encrypts the plaintext
 * with the cleartext header as associated data. A FRESH random 12-byte nonce is drawn per seal — the
 * AEAD is catastrophic under (key, nonce) reuse; this is the AEAD's first production caller, so the
 * nonce is generated here, never caller-supplied. `openSealed` reverses it and fails closed on any
 * mismatch.
 *
 * BINDING (ADR-0028): the working key is bound to the suite (no cross-suite/downgrade key reuse), the
 * KEM-id, the exact KEM ciphertext, and BOTH party ids (no unknown-key-share). A change to any bound
 * field derives a different key, so the GCM tag fails and `openSealed` throws. The hybrid combiner
 * itself is the audited `@noble/post-quantum/hybrid` (IETF X-Wing) construction; ML-KEM implicit
 * rejection means a tampered ciphertext or wrong key decapsulates to a pseudo-random secret (never the
 * original), which the tag check then rejects.
 *
 * SCOPE / HONESTY: this provides CONFIDENTIALITY + INTEGRITY *to the recipient*, NOT sender
 * authentication — anyone holding the recipient's public key can seal, so `senderId` is a bound
 * CONTEXT claim, not a proof of origin. For authenticated origin, sign the `SealedMessage` separately
 * (e.g. with the suite signer). UNAUDITED reference construction.
 */

import { getKem } from './kem.js'
import { AES_256_GCM, HKDF_SHA384, randomBytes } from './symmetric.js'
import { encodeCanonical } from './cbor.js'
import { DOMAIN_TAGS } from './domains.js'
import type { Bytes } from './types.js'

const SEAL_LABEL = DOMAIN_TAGS.KEM_SEAL
const SEAL_VERSION = 1

export interface SealParams {
  readonly suite: string
  readonly kemId: string
  readonly senderId: string
  readonly recipientId: string
}

export interface SealedMessage {
  readonly suite: string
  readonly kemId: string
  readonly senderId: string
  readonly recipientId: string
  /** KEM encapsulation ciphertext (the recipient decapsulates this). */
  readonly kemCiphertext: Bytes
  /** Fresh per-seal AES-GCM nonce (12 bytes). */
  readonly nonce: Bytes
  /** AES-256-GCM ciphertext including the 16-byte authentication tag. */
  readonly ciphertext: Bytes
}

// All binding below uses canonical CBOR — length-prefixed + injective (distinct field tuples never
// collide into the same info/AAD; see crypto/test/cbor-determinism injectivity + R7) — so the domain
// separation is unambiguous (council seal-review #1).

/**
 * ADR-0028 KDF `info`: canonical CBOR binding label + version + suite + KEM-id + the RECIPIENT PUBLIC
 * KEY + KEM ciphertext + both party ids. Binding the recipient public key is HPKE-style defense in
 * depth over the KEM's own pk-binding (X-Wing combiner + ML-KEM FO transform), closing unknown-key-
 * share at the application layer (council seal-review #3).
 */
function sealInfo(p: SealParams, recipientPublicKey: Bytes, kemCiphertext: Bytes): Bytes {
  return encodeCanonical([
    SEAL_LABEL,
    SEAL_VERSION,
    p.suite,
    p.kemId,
    recipientPublicKey,
    kemCiphertext,
    p.senderId,
    p.recipientId,
  ])
}

/** AEAD associated data — binds the transmitted cleartext header (incl. VERSION + recipient pubkey). */
function sealAad(p: SealParams, recipientPublicKey: Bytes, kemCiphertext: Bytes): Bytes {
  return encodeCanonical([
    SEAL_LABEL,
    SEAL_VERSION,
    p.suite,
    p.kemId,
    recipientPublicKey,
    p.senderId,
    p.recipientId,
    kemCiphertext,
  ])
}

/** Seal `plaintext` to the recipient's hybrid-KEM public key (ADR-0028). */
export function sealToKem(
  recipientKemPublicKey: Bytes,
  plaintext: Bytes,
  params: SealParams,
): SealedMessage {
  const kem = getKem(params.kemId)
  const { cipherText: kemCiphertext, sharedSecret } = kem.encapsulate(recipientKemPublicKey)
  const key = HKDF_SHA384.derive(
    sharedSecret,
    new Uint8Array(0),
    sealInfo(params, recipientKemPublicKey, kemCiphertext),
    AES_256_GCM.keyLength,
  )
  const nonce = randomBytes(AES_256_GCM.nonceLength)
  const ciphertext = AES_256_GCM.seal(
    key,
    nonce,
    plaintext,
    sealAad(params, recipientKemPublicKey, kemCiphertext),
  )
  return {
    suite: params.suite,
    kemId: params.kemId,
    senderId: params.senderId,
    recipientId: params.recipientId,
    kemCiphertext,
    nonce,
    ciphertext,
  }
}

/**
 * Open a {@link SealedMessage} with the recipient's KEM secret key. The relying party MUST declare the
 * `suite` and `recipientId` it expects; a mismatch fails closed before any crypto. Throws on a
 * tampered ciphertext, wrong key, or any altered bound field (GCM tag failure).
 */
export function openSealed(
  sealed: SealedMessage,
  recipient: { readonly publicKey: Bytes; readonly secretKey: Bytes },
  expected: { suite: string; recipientId: string },
): Bytes {
  if (sealed.suite !== expected.suite)
    throw new Error('sealed message: suite mismatch (downgrade?)')
  if (sealed.recipientId !== expected.recipientId) {
    throw new Error('sealed message: recipient mismatch (not addressed to this party)')
  }
  const kem = getKem(sealed.kemId)
  const sharedSecret = kem.decapsulate(sealed.kemCiphertext, recipient.secretKey)
  const params: SealParams = {
    suite: sealed.suite,
    kemId: sealed.kemId,
    senderId: sealed.senderId,
    recipientId: sealed.recipientId,
  }
  const key = HKDF_SHA384.derive(
    sharedSecret,
    new Uint8Array(0),
    sealInfo(params, recipient.publicKey, sealed.kemCiphertext),
    AES_256_GCM.keyLength,
  )
  return AES_256_GCM.open(
    key,
    sealed.nonce,
    sealed.ciphertext,
    sealAad(params, recipient.publicKey, sealed.kemCiphertext),
  )
}
