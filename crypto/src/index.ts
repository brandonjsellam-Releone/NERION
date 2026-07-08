// SPDX-FileCopyrightText: 2026 TRELYAN
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @polarseek/crypto — post-quantum, crypto-agile primitives behind a SuiteID.
 *
 * P0 reference implementation in TypeScript over the audited `@noble` libraries.
 * The Rust hot-path implementation tracks this same SuiteID contract (ADR-0002).
 *
 * Govern the verb, never the eye. Post-quantum all the way down.
 */

export * from './types.js'
export * from './errors.js'
export {
  randomBytes,
  constantTimeEqual,
  AES_256_GCM,
  HMAC_SHA384,
  HKDF_SHA384,
  SHA3_SHAKE256,
} from './symmetric.js'
export { encodeCanonical, decodeCbor, decodeCanonical, canonicalRoundTrip } from './cbor.js'
export { KEM_IDS, getKem, implementedKemIds } from './kem.js'
export type { KemId } from './kem.js'
export { sealToKem, openSealed } from './seal.js'
export type { SealedMessage, SealParams } from './seal.js'
export { SIG_IDS, getSigner, implementedSigIds } from './sign.js'
export type { SigId } from './sign.js'
export {
  getCodeSigner,
  assertSingleTree,
  CODE_SIG_IDS,
  implementedCodeSigIds,
} from './code-sign.js'
export type { CodeSigner, HbsParams, HbsHash, CodeSigId } from './code-sign.js'
export {
  coseSign1,
  coseSign1Verify,
  encodeCoseSign1,
  decodeCoseSign1,
  signEatResult,
  COSE_ALG,
  COSE_PROFILE,
  coseProfileAad,
  EAT_CLAIM,
} from './cose.js'
export type { CoseSign1 } from './cose.js'
export {
  DOMAIN_TAGS,
  DOMAIN_TAGS_V2,
  DOMAIN_TAGS_V3,
  PROTOCOL_TAG_GENERATION,
  domainTagsFor,
  allDomainTags,
} from './domains.js'
export type { DomainTag, TagGeneration } from './domains.js'
export {
  SUITE_IDS,
  getSuite,
  allSuites,
  activeSuiteIds,
  negotiate,
  negotiationTranscript,
  verifyNegotiationTranscript,
  kemFor,
  signerFor,
} from './suites.js'
export type { SuiteId, NegotiationContext } from './suites.js'
export { assessCnsa20 } from './cnsa.js'
export type { CnsaAssessment, CnsaFinding, CnsaStatus } from './cnsa.js'
export {
  signEnvelope,
  signEnvelopeWith,
  verifyEnvelope,
  openEnvelope,
  issuePermit,
  verifyPermit,
  permitMac,
  readPermit,
  deriveAudiencePermitKey,
} from './envelope.js'
export type { SignedEnvelope, PermitToken } from './envelope.js'
