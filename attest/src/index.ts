// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/attest — RATS-style session attestation (software root + TEE stubs).
 */

export type {
  AttestationFormat,
  AttestationClaims,
  Evidence,
  AppraisalPolicy,
  AppraisalResult,
  QuoteVerdict,
  QuoteVerifier,
} from './types.js'
export { SoftwareAttester, appraise, appraiseNofM } from './software.js'
export { QuoteVerifierRegistry } from './verifiers.js'
