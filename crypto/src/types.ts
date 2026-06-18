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
  sign(message: Bytes, secretKey: Bytes): Bytes
  verify(signature: Bytes, message: Bytes, publicKey: Bytes): boolean
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
