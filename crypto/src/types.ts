// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Core crypto-agility interfaces for PolarSeek.
 *
 * Every signed or encrypted object in PolarSeek carries a negotiable `SuiteId`
 * (see {@link ./suites.ts}). Concrete primitives are reached only through these
 * interfaces so that no algorithm is hard-coded into protocol logic — the
 * mandate from the build spec's guardrail #3 ("crypto-agility is mandatory").
 */

export type Bytes = Uint8Array

export interface KeyPair {
  readonly publicKey: Bytes
  readonly secretKey: Bytes
}

export interface Encapsulation {
  /** Ciphertext to send to the holder of the secret key. */
  readonly cipherText: Bytes
  /** Symmetric shared secret derived by the encapsulator. */
  readonly sharedSecret: Bytes
}

/**
 * Key Encapsulation Mechanism. PolarSeek only registers *hybrid* KEMs
 * (a classical ECDH leg + a PQ lattice leg, combined by a vetted KDF) so that
 * a break of either leg alone does not break the shared secret.
 */
export interface Kem {
  readonly id: string
  readonly lengths: Readonly<Record<string, number>>
  /** Deterministic when `seed` is supplied (used by KAT vectors). */
  keygen(seed?: Bytes): KeyPair
  /** Deterministic when `coins` is supplied (used by KAT vectors). */
  encapsulate(publicKey: Bytes, coins?: Bytes): Encapsulation
  decapsulate(cipherText: Bytes, secretKey: Bytes): Bytes
}

/** Digital signature scheme (ML-DSA-87 general; SLH-DSA for long-term roots). */
export interface SignatureScheme {
  readonly id: string
  readonly lengths: Readonly<Record<string, number>>
  keygen(seed?: Bytes): KeyPair
  /**
   * Sign `message`. The optional `context` is the FIPS-204/205 context string
   * (≤255 bytes) for domain separation — e.g. distinguishing a permit signature
   * from a receipt or root signature. Omitting it uses the empty context (the
   * FIPS default), which is byte-identical to the prior 2-arg behavior, so pinned
   * KAT vectors (no-context) are unaffected.
   */
  sign(message: Bytes, secretKey: Bytes, context?: Bytes): Bytes
  /** Verify; `context` MUST match the one used at signing (empty if omitted). */
  verify(signature: Bytes, message: Bytes, publicKey: Bytes, context?: Bytes): boolean
}

/** Authenticated encryption with associated data (AES-256-GCM on the hot path). */
export interface Aead {
  readonly id: string
  readonly keyLength: number
  readonly nonceLength: number
  readonly tagLength: number
  seal(key: Bytes, nonce: Bytes, plaintext: Bytes, aad?: Bytes): Bytes
  /** Throws {@link VerificationError} on tag mismatch — never returns garbage. */
  open(key: Bytes, nonce: Bytes, ciphertext: Bytes, aad?: Bytes): Bytes
}

/** Message authentication code (HMAC-SHA-384 for Plane-1 PermitTokens). */
export interface Mac {
  readonly id: string
  readonly tagLength: number
  compute(key: Bytes, message: Bytes): Bytes
  /** Constant-time comparison. */
  verify(key: Bytes, message: Bytes, tag: Bytes): boolean
}

/**
 * Key derivation function (HKDF-SHA-384, RFC 5869). Used to derive per-audience
 * Plane-1 PermitToken keys from the session secret so a key-holding resource
 * cannot forge a permit for a different audience (ADR-0015). `info` binds the
 * derived key to its usage context; `salt` may be empty per RFC 5869 §2.2.
 */
export interface Kdf {
  readonly id: string
  derive(ikm: Bytes, salt: Bytes, info: Bytes, length: number): Bytes
}

/** Cryptographic hash / XOF (SHA3-256 fixed digest, SHAKE256 extendable). */
export interface HashFn {
  readonly id: string
  digest(message: Bytes): Bytes
  xof(message: Bytes, outputLength: number): Bytes
}

export type SuiteStatus = 'active' | 'pending-standardization' | 'not-load-bearing' | 'deprecated'

/** Security category in NIST PQC terms (Cat-1 ≈ AES-128 … Cat-5 ≈ AES-256). */
export type SecurityCategory = 1 | 3 | 5

export interface Suite {
  readonly id: string
  readonly status: SuiteStatus
  readonly category: SecurityCategory
  /** Lower number = higher negotiation preference. */
  readonly preference: number
  readonly kemId: string
  readonly sigId: string
  readonly aeadId: string
  readonly macId: string
  readonly hashId: string
  readonly description: string
  /** Notes on standards alignment (CNSA 2.0, FIPS, IETF X-Wing, etc.). */
  readonly standards: string
}
