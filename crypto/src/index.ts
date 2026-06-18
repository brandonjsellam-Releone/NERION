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
  SHA3_SHAKE256,
} from './symmetric.js'
export { encodeCanonical, decodeCbor, canonicalRoundTrip } from './cbor.js'
export { KEM_IDS, getKem, implementedKemIds } from './kem.js'
export type { KemId } from './kem.js'
export { SIG_IDS, getSigner, implementedSigIds } from './sign.js'
export type { SigId } from './sign.js'
export {
  SUITE_IDS,
  getSuite,
  allSuites,
  activeSuiteIds,
  negotiate,
  kemFor,
  signerFor,
} from './suites.js'
export type { SuiteId } from './suites.js'
export {
  signEnvelope,
  verifyEnvelope,
  openEnvelope,
  issuePermit,
  verifyPermit,
  readPermit,
} from './envelope.js'
export type { SignedEnvelope, PermitToken } from './envelope.js'
