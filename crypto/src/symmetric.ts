/**
 * Symmetric primitives for the hot path and hashing.
 *
 *   - AEAD:  AES-256-GCM            (key 32 / nonce 12 / tag 16)
 *   - MAC:   HMAC-SHA-384          (PermitToken authentication, Plane 1)
 *   - Hash:  SHA3-256 + SHAKE256   (commitments, KDF transcripts)
 *
 * Primitives come from the audited `@noble` libraries; we never roll our own.
 */

import { gcm } from '@noble/ciphers/aes.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha384 } from '@noble/hashes/sha2.js'
import { sha3_256, shake256 } from '@noble/hashes/sha3.js'
import { randomBytes as nodeRandomBytes } from 'node:crypto'

import type { Aead, Bytes, HashFn, Mac } from './types.js'
import { VerificationError } from './errors.js'

/** Cryptographically secure random bytes (CSPRNG via Node's crypto). */
export function randomBytes(length: number): Bytes {
  return new Uint8Array(nodeRandomBytes(length))
}

/**
 * Constant-time byte comparison. Returns false for unequal lengths without
 * leaking *where* the mismatch is via early exit.
 */
export function constantTimeEqual(a: Bytes, b: Bytes): boolean {
  if (a.length !== b.length) return false
  let diff = 0
  for (let i = 0; i < a.length; i++) {
    // Both indices are in-bounds by the length check above.
    diff |= (a[i] as number) ^ (b[i] as number)
  }
  return diff === 0
}

export const AES_256_GCM: Aead = {
  id: 'AES-256-GCM',
  keyLength: 32,
  nonceLength: 12,
  tagLength: 16,
  seal(key, nonce, plaintext, aad) {
    return gcm(key, nonce, aad).encrypt(plaintext)
  },
  open(key, nonce, ciphertext, aad) {
    try {
      return gcm(key, nonce, aad).decrypt(ciphertext)
    } catch (cause) {
      throw new VerificationError('AES-256-GCM authentication tag verification failed')
    }
  },
}

export const HMAC_SHA384: Mac = {
  id: 'HMAC-SHA-384',
  tagLength: 48,
  compute(key, message) {
    return hmac(sha384, key, message)
  },
  verify(key, message, tag) {
    return constantTimeEqual(hmac(sha384, key, message), tag)
  },
}

export const SHA3_SHAKE256: HashFn = {
  id: 'SHA3-256/SHAKE256',
  digest(message) {
    return sha3_256(message)
  },
  xof(message, outputLength) {
    return shake256(message, { dkLen: outputLength })
  },
}
