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
