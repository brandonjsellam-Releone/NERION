/**
 * TEE quote-verifier adapter registry.
 *
 * Real hardware attestation (TDX / SEV-SNP / CCA) plugs in here: register a
 * {@link QuoteVerifier} for a format and the appraisal pipeline will use it
 * (checking the quote + enclave measurement against policy). With no verifier
 * registered, hardware formats are rejected — see {@link ./software.appraise}.
 */

import type { AttestationFormat, QuoteVerifier } from './types.js'

export class QuoteVerifierRegistry {
  private readonly verifiers = new Map<string, QuoteVerifier>()

  register(v: QuoteVerifier): this {
    this.verifiers.set(v.format, v)
    return this
  }

  get(format: AttestationFormat): QuoteVerifier | undefined {
    return this.verifiers.get(format)
  }
}
