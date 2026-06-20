// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * PolarSeek crypto error taxonomy.
 *
 * All errors carry a stable `code` so callers (and the CI non-infringement
 * linter) can branch on machine-readable identifiers rather than message text.
 */

export class PolarCryptoError extends Error {
  readonly code: string
  constructor(code: string, message: string) {
    super(message)
    this.name = 'PolarCryptoError'
    this.code = code
  }
}

/** A SuiteID was requested that is not present in the registry. */
export class UnknownSuiteError extends PolarCryptoError {
  constructor(id: string) {
    super('E_UNKNOWN_SUITE', `unknown SuiteID: ${id}`)
    this.name = 'UnknownSuiteError'
  }
}

/**
 * A registered-but-not-yet-implemented primitive was instantiated.
 *
 * This is how crypto-agility placeholders (HQC backup KEM, Falcon/FN-DSA
 * receipts) fail loudly instead of silently degrading. The `connect` field
 * points the operator at what must be wired in.
 */
export class NotImplementedError extends PolarCryptoError {
  readonly connect: string
  constructor(what: string, connect: string) {
    super('E_NOT_IMPLEMENTED', `${what} is registered but not implemented (CONNECT: ${connect})`)
    this.name = 'NotImplementedError'
    this.connect = connect
  }
}

/** Negotiation failed: no mutually-supported active suite. */
export class NoCommonSuiteError extends PolarCryptoError {
  constructor() {
    super('E_NO_COMMON_SUITE', 'no mutually-supported active SuiteID')
    this.name = 'NoCommonSuiteError'
  }
}

/** A signed/MAC'd object failed verification. */
export class VerificationError extends PolarCryptoError {
  constructor(message: string) {
    super('E_VERIFICATION', message)
    this.name = 'VerificationError'
  }
}

/** A crypto policy was violated (e.g. multi-tree HBS for CNSA 2.0 code signing). */
export class PolicyError extends PolarCryptoError {
  constructor(code: string, message: string) {
    super(code, message)
    this.name = 'PolicyError'
  }
}

/** A one-time-key HBS one-time-key tree is exhausted (all 2^H leaves consumed). */
export class OtsKeyExhaustedError extends PolarCryptoError {
  constructor(keyId: string) {
    super(
      'E_OTS_EXHAUSTED',
      `one-time-key HBS key ${keyId} exhausted; rotate to a fresh single-tree key`,
    )
    this.name = 'OtsKeyExhaustedError'
  }
}

/** A one-time-key HBS signing state was cloned (two writers / a restored snapshot). */
export class OtsStateClonedError extends PolarCryptoError {
  constructor(keyId: string) {
    super(
      'E_OTS_CLONED',
      `one-time-key HBS key ${keyId} state was cloned (conflicting writer epoch); a reused OTS index forges — refusing`,
    )
    this.name = 'OtsStateClonedError'
  }
}

/** A one-time-key HBS signing state rolled back below its monotonic floor. */
export class OtsStateRollbackError extends PolarCryptoError {
  constructor(keyId: string) {
    super(
      'E_OTS_ROLLBACK',
      `one-time-key HBS key ${keyId} state rolled back below its monotonic floor; a reused OTS index forges — refusing`,
    )
    this.name = 'OtsStateRollbackError'
  }
}
