/**
 * RATS-style attestation (RFC 9334 roles).
 *
 * An Attester produces Evidence binding a session identity key + a
 * verifier-supplied nonce; a Verifier appraises it against a policy (trusted
 * attesters, accepted formats, nonce freshness, expiry). Session-scoped: attest
 * at context establishment, mint a short-lived key, re-attest for high tiers.
 *
 * The `software-dev` format is fully implemented (a software root of trust /
 * EU-sovereign-TPM-style option). Hardware TEE formats (TDX / SEV-SNP / CCA)
 * are honest stubs — appraising them fails with a CONNECT pointer until a real
 * quote-verification adapter is wired.
 */

import type { Bytes } from '../../crypto/src/index.js'

export type AttestationFormat = 'software-dev' | 'tdx' | 'sev-snp' | 'cca' | 'tpm'

export interface AttestationClaims {
  readonly format: AttestationFormat
  readonly sessionId: string
  /** hex of the session identity key (= the capability holder/subject). */
  readonly sessionPublicKey: string
  /** hex, verifier-supplied freshness challenge. */
  readonly nonce: string
  /** unix seconds; appraised against an explicit `now`. */
  readonly notAfter: number
  /** enclave measurement (hex) — present for TEE formats. */
  readonly measurement?: string
}

export interface Evidence {
  readonly claims: AttestationClaims
  readonly format: AttestationFormat
  readonly attesterPublicKey: Bytes
  readonly sig: Bytes
  readonly suite: string
}

export interface AppraisalPolicy {
  readonly expectedNonce: string
  readonly now: number
  readonly trustedAttesters: readonly Bytes[]
  readonly acceptedFormats: readonly AttestationFormat[]
}

export interface AppraisalResult {
  readonly valid: boolean
  readonly reasons: string[]
  readonly claims: AttestationClaims | null
}
