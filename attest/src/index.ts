/**
 * @polarseek/attest — RATS-style session attestation (software root + TEE stubs).
 */

export type {
  AttestationFormat,
  AttestationClaims,
  Evidence,
  AppraisalPolicy,
  AppraisalResult,
} from './types.js'
export { SoftwareAttester, appraise, appraiseNofM } from './software.js'
